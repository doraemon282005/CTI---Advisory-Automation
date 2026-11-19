import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from inventory_manager import ApplicationInventory
from ai_evaluator import SecurityAIEvaluator, extract_cvss_score

inv_path = Path(__file__).resolve().parent.parent / "Unique Application Names.xlsx"
if not inv_path.exists():
    inv_path = Path(__file__).resolve().parent / "inventory.xlsx"

inventory = ApplicationInventory(str(inv_path))
evaluator = SecurityAIEvaluator()

adjacent_sentence_match = inventory.match(
    "Security advisory details released",
    "Apache Tomcat is affected. A vulnerability in its AJP connector could expose data."
)
assert any("tomcat" in match["application_name"].lower() for match in adjacent_sentence_match), (
    "Expected the inventory's Tomcat entry to match when product and vulnerability details are in adjacent sentences"
)
print("[PASS] Product mention matches adjacent-sentence vulnerability context")

test_cases = [
    {
        "title": "Malicious Chrome Extension Steals Session Tokens from Corporate Users",
        "content": "Security researchers uncovered a malicious browser extension on the Chrome Web Store affecting millions.",
        "expected": "FILTER OUT (Browser extension excluded by policy)"
    },
    {
        "title": "Now ChatGPT Chrome Extension Can See and Analyze the Content in Open Tabs",
        "content": "OpenAI has updated its ChatGPT Chrome extension to allow it to read web pages and open tabs for productivity analysis.",
        "expected": "FILTER OUT (Browser extension / feature news)"
    },
    {
        "title": "Tens of thousands of Nvidia GPUs sit idle in Meta's new data centers",
        "content": "Due to cooling and power issues, thousands of GPUs are waiting. Monitoring tools like Prometheus recorded low cluster usage.",
        "expected": "FILTER OUT (Data center news, incidental Prometheus mention)"
    },
    {
        "title": "PHP2Shell: Two Unpatched Critical PHP RCE Flaws (CVSS 9.2) Trigger Emergency Security Alert",
        "content": "Two critical remote code execution vulnerabilities in PHP core allow unauthenticated remote attackers to execute arbitrary shell commands.",
        "expected": "ACCEPT (Genuine Critical RCE for PHP | CVSS: 9.2)"
    },
    {
        "title": "CVE-2026-103119: Apache Tomcat: AJP response mix-up vulnerability",
        "content": "When Apache Tomcat is configured with the AJP connector, an attacker could craft malformed packets to cause data leakage. CVSS Base Score: 7.5 (High).",
        "expected": "ACCEPT (Genuine CVE for Apache Tomcat | CVSS: 7.5)"
    },
    {
        "title": "Critical Authentication Bypass in Palo Alto PAN-OS GlobalProtect (CVE-2026-1192)",
        "content": "An unauthenticated remote attacker can bypass authentication on the GlobalProtect portal to execute arbitrary commands as root. CVSS v3.1: 9.8.",
        "expected": "ACCEPT (Genuine Critical Auth Bypass for GlobalProtect | CVSS: 9.8)"
    }
]

print("=" * 70)
print("TESTING TRIAGE, EXTENSION FILTERING & CVSS EXTRACTION")
print("=" * 70)

for idx, tc in enumerate(test_cases, 1):
    print(f"\nTest {idx}: {tc['title']}")
    print(f"  Expected: {tc['expected']}")
    
    matches = inventory.match(tc["title"], tc["content"])
    if not matches:
        print("  -> RESULT: [FILTERED OUT at Step 1: No contextual vulnerability / Extension excluded]")
        continue
        
    primary = matches[0]
    evaluation = evaluator.evaluate_advisory(tc, primary)
    is_actionable = evaluation.get("is_actionable_vulnerability", True)
    
    if not is_actionable:
        reason = evaluation.get("rejection_reason", "Not actionable")
        print(f"  -> RESULT: [FILTERED OUT at Step 2 by Triage Engine]: {reason}")
    else:
        cvss = evaluation.get('cvss_score')
        print(f"  -> RESULT: [ACCEPTED]: Matched App: {primary['application_name']}")
        print(f"     Heading:  {evaluation.get('advisory_heading')}")
        print(f"     Severity: {evaluation.get('severity')} | CVSS: {cvss}")
        print(f"     Summary:  {evaluation.get('impact_summary')}")
