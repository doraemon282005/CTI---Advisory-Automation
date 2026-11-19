import os
import json
import re
import requests
import urllib3
from typing import Dict, Any, Optional

NON_ACTIONABLE_CONTEXT_PATTERNS = (
    r'\b(?:chrome|browser|edge|firefox)\s+(?:extension|extensions|addon|add-on|add-ons|plugin|plugins|web store)\b',
    r'\b(?:open tabs|web pages|read.*web pages|read.*browser content|web content)\b',
    r'\b(?:data center|data centres|gpu|gpus)\b.*\b(?:sit idle|idle in|waiting|cooling|power issues)\b',
    r'\b(?:new feature|feature update|introducing|launches|rolling out|major release|announces)\b',
    r'\b(?:lawsuit|court case|settles with|layoffs|earnings report|merger|acquisition|startup claims)\b',
)

def limit_summary_words(text: str, limit: int = 500) -> str:
    """Limit generated summaries to a maximum word count."""
    words = re.findall(r"\S+", str(text or "").strip())
    if len(words) <= limit:
        return str(text or "").strip()
    return " ".join(words[:limit]).rstrip(" \t\r\n,.;:-") + "."

def extract_cvss_score(text: str) -> str:
    """
    Robust multi-pattern extractor for CVSS base scores from advisory text.
    Handles varied formats: '(CVSS 9.2)', 'CVSSv3: 8.8', 'CVSS score of 7.5',
    'rated 9.8', vector strings, etc.
    """
    if not text:
        return ""

    # Pattern 1: CVSS followed by score: (CVSS 9.2), CVSS: 9.8, CVSS:3.1 8.8, CVSSv3 7.5
    m = re.search(r'\bcvss(?:v[23](?:\.[01])?)?[:\s\(\[=-]+([0-9]\.[0-9])\b', text, re.IGNORECASE)
    if m:
        return m.group(1)

    # Pattern 2: Score followed by /10 or CVSS: '9.8 out of 10', '9.8 / 10', '9.8 CVSS'
    m = re.search(r'\b([0-9]\.[0-9])\s*(?:\/\s*10|out of 10|\bcvss\b)', text, re.IGNORECASE)
    if m:
        return m.group(1)

    # Pattern 3: 'CVSS Base Score of 8.6' or 'CVSS score of 7.5'
    m = re.search(r'\bcvss(?:\s+base)?\s+score\s+(?:of\s+)?([0-9]\.[0-9])\b', text, re.IGNORECASE)
    if m:
        return m.group(1)

    # Pattern 4: 'rated 9.8' or 'severity score: 8.5' or 'severity: 9.8'
    m = re.search(r'\b(?:rated|severity\s+score|severity)\s*(?:of|:)?\s*([0-9]\.[0-9])\b', text, re.IGNORECASE)
    if m:
        return m.group(1)

    # Pattern 5: Bracketed score: [9.8] or (9.8) in proximity to vulnerability
    m = re.search(r'\b(?:vulnerability|flaw|rce)\s*[^\n\.\(]*\(([0-9]\.[0-9])\)', text, re.IGNORECASE)
    if m:
        return m.group(1)

    return ""


class SecurityAIEvaluator:
    """
    AI-powered Cyber Threat Intelligence (CTI) Triage & Evaluation Engine.
    Filters out noise/tangential news and extracts structured, actionable intelligence
    (CVE, CVSS, Severity, Attack Vector, Root Cause, Remediation) for inventory assets.
    """
    def __init__(self, api_key: str = "", model_name: str = "gemini-2.5-flash", 
                 openai_api_key: str = "", verify_ssl: bool = False):
        self.gemini_key = api_key.strip() or os.getenv("GEMINI_API_KEY", "").strip()
        self.openai_key = openai_api_key.strip() or os.getenv("OPENAI_API_KEY", "").strip()
        self.model_name = model_name or "gemini-2.5-flash"
        self.verify_ssl = verify_ssl

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @staticmethod
    def limit_summary_words(text: str, limit: int = 500) -> str:
        return limit_summary_words(text, limit)

    def _reject_non_actionable_context(self, text: str, matched_app: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """Reject general-interest or product-update stories before LLM or rule-based evaluation."""
        text_lower = text.lower()

        if re.search(r'\b(?:chrome|browser|edge|firefox)\s+(?:extension|extensions|addon|add-on|add-ons|plugin|plugins|web store)\b', text_lower):
            if re.search(r'\b(?:read|access|analyz|analyze|inspect|open)\b.*\b(?:web pages|open tabs|browser content|tab content)\b', text_lower):
                return {
                    "is_actionable_vulnerability": False,
                    "rejection_reason": "Browser extension / add-on feature update, not a security advisory"
                }
            return {
                "is_actionable_vulnerability": False,
                "rejection_reason": "Browser extension / add-on vulnerability (Excluded by infrastructure policy)"
            }

        if re.search(r'\b(?:data center|data centres|gpu|gpus)\b', text_lower) and re.search(r'\b(?:sit idle|idle in|waiting|cooling|power issues)\b', text_lower):
            return {
                "is_actionable_vulnerability": False,
                "rejection_reason": "Infrastructure / capacity news, not a security vulnerability"
            }

        if re.search(r'\b(?:new feature|feature update|introducing|launches|rolling out|major release|announces)\b', text_lower):
            if not re.search(r'\b(?:vulnerability|vulnerabilities|flaw|flaws|exploit|exploits|rce|zero-day|0-day|patch|patched|security advisory|cve-\d{4}-\d+)\b', text_lower):
                return {
                    "is_actionable_vulnerability": False,
                    "rejection_reason": "General product/news update without a concrete vulnerability"
                }

        if matched_app and matched_app.get('application_name'):
            app_name = matched_app['application_name']
            if app_name.lower() not in text_lower and 'cve-' not in text_lower and not re.search(r'\b(?:vulnerability|security update|patch|exploit|rce|bypass)\b', text_lower):
                return {
                    "is_actionable_vulnerability": False,
                    "rejection_reason": "Matched application is not discussed as a security issue"
                }

        return None

    def evaluate_advisory(self, advisory: Dict[str, Any], matched_app: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates the advisory.
        Returns dictionary including 'is_actionable_vulnerability' flag.
        If the article is not a legitimate security advisory for the matched app,
        is_actionable_vulnerability is False so it will be dropped.
        """
        # 2. Try Gemini API if key is present
        if self.gemini_key:
            try:
                ai_result = self._call_gemini(advisory, matched_app)
                if ai_result:
                    translated_text = (
                        f"{ai_result['translated_title']}\n"
                        f"{ai_result['translated_content']}"
                    )
                    non_actionable = self._reject_non_actionable_context(
                        translated_text,
                        matched_app,
                    )
                    if non_actionable:
                        return {**ai_result, **non_actionable}
                    return ai_result
            except Exception as e:
                print(f"[AI Evaluator] Gemini API call error: {e}. Falling back to rule engine.")

        # 3. Try OpenAI API if key is present
        if self.openai_key:
            try:
                ai_result = self._call_openai(advisory, matched_app)
                if ai_result:
                    translated_text = (
                        f"{ai_result['translated_title']}\n"
                        f"{ai_result['translated_content']}"
                    )
                    non_actionable = self._reject_non_actionable_context(
                        translated_text,
                        matched_app,
                    )
                    if non_actionable:
                        return {**ai_result, **non_actionable}
                    return ai_result
            except Exception as e:
                print(f"[AI Evaluator] OpenAI API call error: {e}. Falling back to rule engine.")

        title = advisory.get("title", "")
        content = advisory.get("content", "")
        non_actionable = self._reject_non_actionable_context(
            f"{title}\n{content}",
            matched_app,
        )
        if non_actionable is not None:
            return non_actionable

        # 4. Enhanced CTI Heuristic Filter & Evaluator
        return self._rule_based_fallback(advisory, matched_app)

    def _call_gemini(self, advisory: Dict[str, Any], matched_app: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent?key={self.gemini_key}"
        app_name = matched_app.get('application_name', 'Application')
        vendor = matched_app.get('vendor', '')

        prompt = f"""
You are an expert Cyber Threat Intelligence (CTI) Analyst at an Enterprise SOC.
Review the following security advisory and determine if it represents an ACTUAL, ACTIONABLE security vulnerability, exploit, or patch affecting the infrastructure application: "{app_name}" (Vendor: "{vendor}").

First translate the complete advisory title and content into English. If either is already in English, preserve it as-is. Perform the security analysis using the English translation. Keep CVE identifiers, product names, versions, commands, and URLs unchanged, and do not omit or summarize any source content in the translation. Write all analysis fields in English.

CRITICAL REJECTION RULES:
1. REJECT (is_actionable_vulnerability: false) if:
   - This is about BROWSER EXTENSIONS or ADD-ONS (e.g. Chrome extension, Firefox add-on). Our infrastructure does NOT use browser extensions.
   - This is general tech news, corporate announcements, mergers, court cases, bug bounty rule changes, or opinions.
   - The application "{app_name}" is only mentioned incidentally (e.g. "researchers tested on Chrome", "hackers used PHP script to target WordPress").
   - There is NO concrete vulnerability, exploit, or vendor patch for "{app_name}".
2. ACCEPT (is_actionable_vulnerability: true) ONLY if:
   - There is a concrete vulnerability, exploit, CVE, or security patch directly affecting "{app_name}".

Article Details:
- Title: {advisory.get('title')}
- Source: {advisory.get('source_name')}
- Content: {advisory.get('content')[:15000]}

Respond ONLY with valid JSON:
{{
  "is_actionable_vulnerability": true or false,
  "rejection_reason": "Explain why rejected (if false) or leave empty (if true)",
  "translated_title": "Complete title in English",
  "translated_content": "Complete advisory content in English",
  "advisory_heading": "Clean, standardized title with CVE-YYYY-NNNN if available (e.g. 'Apache Tomcat: RCE via AJP (CVE-2026-103119)')",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "cvss_score": "Exact score (e.g. 9.8, 8.4). If not explicitly mentioned in text, estimate standard base score according to CVSS v3.1 specification for this flaw",
  "affected_products": "Every affected product/component. Include a version range only when explicitly stated; otherwise omit it.",
  "affected_versions": "Explicitly stated affected versions/ranges, or an empty string. Never infer versions or use a vendor-bulletin placeholder.",
  "impact_summary": "Crisp technical classification detail: root cause and actionable impact.",
  "report_summary": "Use no more than 500 words. Write 3-4 concise sentences about the security issue: technical cause, attacker impact/conditions, affected product and versions only when explicitly stated, and remediation only when stated. Exclude marketing, release background, and generic announcements. Use only facts in the advisory."
}}
"""
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json"
            }
        }

        resp = requests.post(url, json=payload, headers={"Content-Type": "application/json"},
                             verify=self.verify_ssl, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            text = data["candidates"][0]["content"]["parts"][0]["text"]
            parsed = json.loads(text)
            translated_title, translated_content = self._get_english_translation(parsed)
            
            # Ensure CVSS is not empty
            cvss_val = parsed.get("cvss_score", "")
            if not cvss_val or str(cvss_val).strip().upper() in ["N/A", "NONE", "UNKNOWN", ""]:
                # Attempt regex extraction from article text
                extracted = extract_cvss_score(f"{advisory.get('title')} {advisory.get('content')}")
                cvss_val = extracted if extracted else self._default_cvss_by_severity(parsed.get("severity", "MEDIUM"))

            affected_products, affected_versions = self._get_affected_details(
                parsed,
                f"{advisory.get('title') or ''}\n{advisory.get('content') or ''}",
                app_name,
            )
            return {
                "is_actionable_vulnerability": parsed.get("is_actionable_vulnerability", True),
                "rejection_reason": parsed.get("rejection_reason", ""),
                "translated_title": translated_title,
                "translated_content": translated_content,
                "advisory_heading": parsed.get("advisory_heading", advisory.get("title")),
                "severity": parsed.get("severity", "HIGH").upper(),
                "cvss_score": str(cvss_val),
                "affected_products": affected_products,
                "affected_versions": affected_versions,
                "impact_summary": parsed.get("impact_summary", ""),
                "report_summary": limit_summary_words(parsed.get("report_summary", "")),
            }
        return None

    def _call_openai(self, advisory: Dict[str, Any], matched_app: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        url = "https://api.openai.com/v1/chat/completions"
        app_name = matched_app.get('application_name', 'Application')
        vendor = matched_app.get('vendor', '')

        prompt = f"""
You are an expert Cyber Threat Intelligence (CTI) Analyst at an Enterprise SOC.
Determine if the following feed article is an actual security vulnerability, exploit, or patch directly affecting "{app_name}" (Vendor: "{vendor}").
Reject if it is about browser extensions (Chrome extensions, add-ons) or general tech news.

First translate the complete advisory title and content into English. If either is already in English, preserve it as-is. Perform the security analysis using the English translation. Keep CVE identifiers, product names, versions, commands, and URLs unchanged, and do not omit or summarize any source content in the translation. Write all analysis fields in English.

Title: {advisory.get('title')}
Content: {advisory.get('content')[:15000]}

Output JSON:
{{
  "is_actionable_vulnerability": true or false,
  "rejection_reason": "...",
  "translated_title": "Complete title in English",
  "translated_content": "Complete advisory content in English",
  "advisory_heading": "...",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW",
  "cvss_score": "Exact or estimated CVSS v3.1 base score (e.g. 9.8)",
  "affected_products": "Every affected product/component. Include a version range only when explicitly stated; otherwise omit it.",
  "affected_versions": "Explicitly stated affected versions/ranges, or an empty string. Never infer versions or use a vendor-bulletin placeholder.",
  "impact_summary": "Technical classification detail: root cause and actionable impact.",
  "report_summary": "Use no more than 500 words. Write 3-4 concise sentences about the security issue: technical cause, attacker impact/conditions, affected product and versions only when explicitly stated, and remediation only when stated. Exclude marketing, release background, and generic announcements. Use only facts in the advisory."
}}
"""
        headers = {
            "Authorization": f"Bearer {self.openai_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"},
            "temperature": 0.1
        }

        resp = requests.post(url, json=payload, headers=headers, verify=self.verify_ssl, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            parsed = json.loads(data["choices"][0]["message"]["content"])
            translated_title, translated_content = self._get_english_translation(parsed)
            
            cvss_val = parsed.get("cvss_score", "")
            if not cvss_val or str(cvss_val).strip().upper() in ["N/A", "NONE", "UNKNOWN", ""]:
                extracted = extract_cvss_score(f"{advisory.get('title')} {advisory.get('content')}")
                cvss_val = extracted if extracted else self._default_cvss_by_severity(parsed.get("severity", "MEDIUM"))

            affected_products, affected_versions = self._get_affected_details(
                parsed,
                f"{advisory.get('title') or ''}\n{advisory.get('content') or ''}",
                app_name,
            )
            return {
                "is_actionable_vulnerability": parsed.get("is_actionable_vulnerability", True),
                "rejection_reason": parsed.get("rejection_reason", ""),
                "translated_title": translated_title,
                "translated_content": translated_content,
                "advisory_heading": parsed.get("advisory_heading", advisory.get("title")),
                "severity": parsed.get("severity", "HIGH").upper(),
                "cvss_score": str(cvss_val),
                "affected_products": affected_products,
                "affected_versions": affected_versions,
                "impact_summary": parsed.get("impact_summary", ""),
                "report_summary": limit_summary_words(parsed.get("report_summary", "")),
            }
        return None

    def _get_english_translation(
        self,
        parsed: Dict[str, Any],
    ):
        translated_title = parsed.get("translated_title")
        translated_content = parsed.get("translated_content")
        if not isinstance(translated_title, str) or not translated_title.strip():
            raise ValueError("AI response did not include an English advisory title.")
        if not isinstance(translated_content, str) or not translated_content.strip():
            raise ValueError("AI response did not include English advisory content.")
        return translated_title.strip(), translated_content.strip()

    def _default_cvss_by_severity(self, severity: str) -> str:
        s = (severity or "MEDIUM").upper()
        if s == "CRITICAL":
            return "9.8 (Base)"
        elif s == "HIGH":
            return "8.2 (Base)"
        elif s == "LOW":
            return "3.5 (Base)"
        return "5.5 (Base)"

    def _get_affected_details(
        self,
        parsed: Dict[str, Any],
        content: str,
        app_name: str,
    ):
        products = str(parsed.get("affected_products") or "").strip()
        versions = str(parsed.get("affected_versions") or "").strip()
        fallback_products, fallback_versions = self._extract_affected_details(
            content,
            app_name,
        )
        if products.casefold() in {
            "", "na", "n/a", "none", "unknown", "see vendor advisory",
            "see vendor bulletin", "check vendor bulletin",
        }:
            products = fallback_products
        if versions.casefold() in {
            "", "na", "n/a", "none", "unknown", "see vendor advisory",
            "see vendor bulletin", "check vendor bulletin",
            "not specified", "not available",
        } or re.fullmatch(
            r"(?:see|check|consult)\s+(?:the\s+)?(?:vendor\s+)?"
            r"(?:advisory|bulletin)(?:\s+for\b.*)?",
            versions,
            re.IGNORECASE,
        ):
            versions = fallback_versions
        if re.fullmatch(
            r".+?\s*:\s*(?:see|check|consult)\s+(?:the\s+)?"
            r"(?:vendor\s+)?(?:advisory|bulletin)"
            r"(?:\s+for\s+(?:the\s+)?affected\s+(?:versions?|releases?))?[.!]?",
            products,
            re.IGNORECASE,
        ):
            products = fallback_products
        return products, versions

    def _build_report_summary(
        self,
        title: str,
        content: str,
        app_name: str,
        severity: str,
        cvss_score: str,
    ) -> str:
        sentences = []
        summary_cues = re.compile(
            r"\b(?:vulnerab\w*|flaw|weakness|exploit\w*|attacker|attack\w*|"
            r"unauth\w*|remote code execution|\brce\b|privilege escalation|"
            r"denial of service|authentication bypass|injection|disclos\w*|"
            r"compromise\w*|bypass|memory corruption|code execution|"
            r"versions?|releases?|cve-\d{4}-\d+|cvss|patch|"
            r"mitigat\w*|workaround)\b",
            re.IGNORECASE,
        )
        for sentence in re.split(r"(?<=[.!?])\s+|\n+", content or ""):
            sentence = re.sub(r"\s+", " ", sentence).strip(" \t\r\n-•")
            if (
                len(sentence) >= 25
                and summary_cues.search(sentence)
                and sentence.casefold() not in {existing.casefold() for existing in sentences}
            ):
                sentences.append(sentence)
            if len(sentences) == 4:
                break

        fallback_lines = [
            f"{title.strip()} affects {app_name}.".strip(),
            f"The advisory describes the following technical impact: {sentences[0]}"
            if sentences else f"The advisory rates the issue {severity} (CVSS {cvss_score}).",
            f"Severity is {severity} with a CVSS score of {cvss_score}.",
            "Consult the linked vendor advisory for remediation details.",
        ]
        for line in fallback_lines:
            if len(sentences) >= 3:
                break
            if line.casefold() not in {existing.casefold() for existing in sentences}:
                sentences.append(line)
        return limit_summary_words("\n".join(sentences[:4]))

    def _extract_affected_details(self, content: str, app_name: str):
        sentences = []
        seen = set()
        for sentence in re.split(r"(?<=[.!?])\s+|\n+", content or ""):
            sentence = re.sub(r"\s+", " ", sentence).strip()
            has_version = re.search(
                r"\bv?\d+(?:\.(?:\d+|x|\*)){0,4}(?:[-+][A-Za-z0-9.*-]+)?\b",
                sentence,
                re.IGNORECASE,
            )
            has_version_context = re.search(
                r"\b(?:versions?|releases?|builds?|branches?)\b",
                sentence,
                re.IGNORECASE,
            )
            has_version_range = re.search(
                r"\b(?:before|prior to|up to|through|between|from|"
                r"or earlier(?: than)?|and earlier|or later|and later)\s+"
                r"(?:version\s+)?v?\d+(?:\.(?:\d+|x|\*)){1,4}\b",
                sentence,
                re.IGNORECASE,
            )
            has_measurement_unit = re.search(
                r"\b\d+(?:\.\d+)?\s*(?:ghz|mhz|gb|mb|tb|cores?|percent|%)\b",
                sentence,
                re.IGNORECASE,
            )
            if (
                has_version
                and (
                    has_version_context
                    or (
                        has_version_range
                        and not has_measurement_unit
                        and re.search(r"\.\d", sentence)
                    )
                )
                and sentence.casefold() not in seen
            ):
                sentences.append(sentence)
                seen.add(sentence.casefold())

        affected_versions = "; ".join(sentences)
        affected_products = "; ".join(
            sentence if app_name.casefold() in sentence.casefold()
            else f"{app_name}: {sentence}"
            for sentence in sentences
        ) or app_name.strip()
        return affected_products, affected_versions

    def _rule_based_fallback(self, advisory: Dict[str, Any], matched_app: Dict[str, Any]) -> Dict[str, Any]:
        """
        Strict heuristic filter that rejects non-vulnerability news, tangential mentions,
        and browser extensions when an LLM API key is not yet configured.
        """
        title = advisory.get("title", "")
        content = advisory.get("content", "")
        full_text = f"{title}\n{content}"
        full_text_lower = full_text.lower()
        app_name = matched_app.get("application_name", "Application")

        # 1. Negative filter: Browser extensions and non-vulnerability product/news updates
        if re.search(r'\b(?:chrome|browser|edge|firefox)\s+(?:extension|extensions|addon|add-on|add-ons|plugin|plugins|web store)\b', full_text_lower):
            return {
                "is_actionable_vulnerability": False,
                "rejection_reason": "Browser extension / add-on vulnerability (Excluded by policy)"
            }

        if re.search(r'\b(?:open tabs|read.*web pages|web pages and open tabs|data center|gpu|gpus)\b', full_text_lower) and not re.search(r'\b(?:vulnerability|vulnerabilities|flaw|exploit|patch|cve|rce|auth bypass|bypass|security update)\b', full_text_lower):
            return {
                "is_actionable_vulnerability": False,
                "rejection_reason": "General news / feature announcement without a concrete vulnerability"
            }

        # 2. Negative filter: Non-vulnerability general news
        non_vulnerability_cues = [
            "bug bounty rules", "bounty reward", "pleads guilty", "sentenced to",
            "lawsuit", "settles with", "sit idle in", "data center investment",
            "startup claims", "layoffs", "earnings report", "shutting down",
            "career advice", "how to configure", "tips and tricks", "best practices",
            "new feature", "launches", "updates its", "can now read", "read web pages"
        ]
        if any(cue in full_text_lower for cue in non_vulnerability_cues):
            if not re.search(r'\b(?:vulnerability|vulnerabilities|flaw|exploit|cve|rce|patch|security advisory|security update)\b', full_text_lower):
                return {
                    "is_actionable_vulnerability": False,
                    "rejection_reason": "General news / Non-vulnerability article"
                }

        # 3. Check for core vulnerability indicators
        cve_match = re.search(r'\bcve-\d{4}-\d+\b', full_text, re.IGNORECASE)
        has_vuln_keywords = any(k in full_text_lower for k in [
            "vulnerability", "vulnerabilities", "flaw", "flaws", "zero-day", "0-day",
            "remote code execution", "rce", "privilege escalation", "authentication bypass",
            "security update", "security advisory", "critical patch"
        ])

        if not cve_match and not has_vuln_keywords:
            return {
                "is_actionable_vulnerability": False,
                "rejection_reason": "No vulnerability or CVE indicators found"
            }

        # 4. Extract CVSS Score using multi-pattern parser
        cvss_score = extract_cvss_score(full_text)

        # 5. Severity calculation
        severity = "MEDIUM"
        if "critical" in full_text_lower or (cvss_score and float(cvss_score.split()[0]) >= 9.0):
            severity = "CRITICAL"
        elif "high" in full_text_lower or "remote code execution" in full_text_lower or "rce" in full_text_lower or (cvss_score and float(cvss_score.split()[0]) >= 7.0):
            severity = "HIGH"
        elif "low" in full_text_lower:
            severity = "LOW"

        # If CVSS wasn't explicitly found in text, provide the standard base estimate for the severity level
        if not cvss_score:
            cvss_score = self._default_cvss_by_severity(severity)

        # 6. Determine vulnerability category
        category = "Security Advisory"
        mechanics = f"Security vulnerability identified affecting {app_name}."
        if any(k in full_text_lower for k in ["remote code execution", "rce"]):
            category = "Remote Code Execution (RCE)"
            mechanics = f"Allows remote attackers to execute arbitrary code on systems running {app_name}."
        elif any(k in full_text_lower for k in ["auth bypass", "authentication bypass"]):
            category = "Authentication Bypass"
            mechanics = f"Allows unauthenticated attackers to bypass access controls in {app_name}."
        elif any(k in full_text_lower for k in ["denial of service", "dos", "crash"]):
            category = "Denial of Service (DoS)"
            mechanics = f"Can cause abnormal service termination or resource exhaustion in {app_name}."
        elif any(k in full_text_lower for k in ["privilege escalation"]):
            category = "Privilege Escalation"
            mechanics = f"Allows authenticated users to gain elevated system privileges in {app_name}."
        elif any(k in full_text_lower for k in ["injection", "sqli"]):
            category = "Injection Vulnerability"
            mechanics = f"Input validation flaw allows command or query injection via {app_name}."

        clean_heading = title.strip()
        clean_heading = re.sub(r'^(\[[^\]]+\]\s*)+', '', clean_heading).strip()
        cve_tag = f" ({cve_match.group(0).upper()})" if cve_match and cve_match.group(0).upper() not in clean_heading else ""

        impact_text = f"[{category}] {mechanics} CVSS score: {cvss_score}. Review vendor patch guidance."
        report_summary = self._build_report_summary(
            clean_heading,
            content,
            app_name,
            severity,
            cvss_score,
        )
        affected_products, affected_versions = self._extract_affected_details(
            full_text,
            app_name,
        )

        return {
            "is_actionable_vulnerability": True,
            "rejection_reason": "",
            "translated_title": clean_heading,
            "translated_content": content,
            "advisory_heading": f"{clean_heading}{cve_tag}",
            "severity": severity,
            "cvss_score": cvss_score,
            "affected_products": affected_products,
            "affected_versions": affected_versions,
            "impact_summary": impact_text,
            "report_summary": report_summary,
        }
