import hashlib
import logging
import math
import re
from copy import deepcopy
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
TOKEN_PATTERN = re.compile(r"[a-z0-9]+")
SENTENCE_PATTERN = re.compile(r"(?<=[.!?])\s+|\n+")
VERSION_PATTERN = re.compile(r"\bv?\d+(?:\.\d+){1,4}\b", re.IGNORECASE)
ENTITY_PATTERN = re.compile(
    r"\b(?:CVE-\d{4}-\d+|[A-Z][A-Za-z0-9._-]*"
    r"(?:\s+[A-Z][A-Za-z0-9._-]*){0,3})\b"
)
STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "by", "can", "for", "from",
    "in", "is", "it", "its", "of", "on", "or", "that", "the", "this",
    "to", "was", "with", "security", "advisory", "vulnerability",
    "vulnerabilities", "issue", "issues", "flaw", "flaws", "affects",
    "affecting", "allow", "allows", "attackers", "attacker", "remote",
    "unauthenticated", "versions", "version", "multiple", "source",
}
ENTITY_STOPWORDS = {
    "remote code execution", "denial of service", "information disclosure",
    "privilege escalation", "security update", "security advisory",
    "zero day", "patch Tuesday", "the", "this", "new", "critical",
}
CONTENT_STOPWORDS = STOPWORDS | {
    "affected", "attack", "base", "bugs", "check", "critical", "execute",
    "execution", "fix", "fixes", "guidance", "identified", "patch",
    "patches", "review", "score", "update", "updates", "vendor",
}
LIFECYCLE_PATTERNS = {
    "disclosure": re.compile(
        r"\b(?:disclos(?:ed|ure)|announc(?:ed|ement)|vulnerability report(?:ed)?)\b",
        re.IGNORECASE,
    ),
    "exploitation": re.compile(
        r"\b(?:actively exploited|exploited in the wild|in-the-wild exploitation|"
        r"weaponiz(?:ed|ation)|attacks exploit|exploitation detected)\b",
        re.IGNORECASE,
    ),
    "patch": re.compile(
        r"\b(?:patch(?:ed|es)?|fixed release|security update|update released|"
        r"remediation available)\b",
        re.IGNORECASE,
    ),
}
VULNERABILITY_CLASSES = (
    ("rce", re.compile(
        r"remote code execution|\brce\b|arbitrary (?:code|command) execution|"
        r"execute arbitrary code",
        re.IGNORECASE,
    )),
    ("dos", re.compile(r"denial.of.service|\bdos\b", re.IGNORECASE)),
    ("privilege_escalation", re.compile(r"privilege escalation", re.IGNORECASE)),
    ("auth_bypass", re.compile(
        r"authentication bypass|authorization bypass|auth bypass",
        re.IGNORECASE,
    )),
    ("injection", re.compile(
        r"sql injection|command injection|code injection|cross.site scripting|xss",
        re.IGNORECASE,
    )),
    ("information_disclosure", re.compile(
        r"information disclosure|sensitive data exposure",
        re.IGNORECASE,
    )),
)


def _tokens(text: Any) -> set:
    cleaned = CVE_PATTERN.sub(" ", str(text or "").casefold())
    return {
        token
        for token in TOKEN_PATTERN.findall(cleaned)
        if len(token) > 2 and token not in STOPWORDS and not token.isdigit()
    }


def _similarity(left: set, right: set) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def _sentence_similarity(left: set, right: set) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / min(len(left), len(right))


def _sentence_identifiers(sentence: str) -> set:
    return {
        *(match.casefold() for match in CVE_PATTERN.findall(sentence)),
        *(match.casefold() for match in VERSION_PATTERN.findall(sentence)),
    }


def _record_cves(record: Dict[str, Any]) -> set:
    text = "\n".join(
        str(record.get(field) or "")
        for field in (
            "advisory_heading",
            "cve_details",
            "impact_summary",
            "report_summary",
            "source_content",
        )
    )
    return {match.upper() for match in CVE_PATTERN.findall(text)}


def _primary_cves(record: Dict[str, Any]) -> set:
    text = "\n".join(
        str(record.get(field) or "")
        for field in ("advisory_heading", "impact_summary")
    )
    return {match.upper() for match in CVE_PATTERN.findall(text)}


def _product_names(record: Dict[str, Any]) -> List[set]:
    title = re.sub(
        r"[^a-z0-9]+",
        "",
        str(record.get("advisory_heading") or "").casefold(),
    )
    names = []
    for field in ("matched_app_name", "affected_products"):
        for name in re.split(r"[,;\n|]", str(record.get(field) or "")):
            terms = _tokens(name)
            normalized = re.sub(r"[^a-z0-9]+", "", name.casefold())
            if terms and normalized and (normalized in title or not names):
                if terms not in names:
                    names.append(terms)
    return names


def _product_similarity(left: Dict[str, Any], right: Dict[str, Any]) -> float:
    left_products = _product_names(left)
    right_products = _product_names(right)
    if not left_products or not right_products:
        return 0.0
    return max(
        _similarity(left_product, right_product)
        for left_product in left_products
        for right_product in right_products
    )


def _title_tokens(record: Dict[str, Any]) -> set:
    references = record.get("source_references") or []
    titles = [str(record.get("advisory_heading") or "")]
    titles.extend(
        str(reference.get("title") or "")
        for reference in references
        if isinstance(reference, dict)
    )
    return set().union(*(_tokens(title) for title in titles))


def _article_tokens(record: Dict[str, Any]) -> set:
    text = "\n".join(
        str(record.get(field) or "")
        for field in (
            "advisory_heading",
            "impact_summary",
            "report_summary",
            "recommendation",
            "source_content",
        )
    )
    text += "\n" + "\n".join(
        f"{reference.get('title', '')} {reference.get('content', '')}"
        for reference in record.get("source_references") or []
        if isinstance(reference, dict)
    )
    tokens = _tokens(text) - CONTENT_STOPWORDS
    for product in _product_names(record):
        tokens.difference_update(product)
    return tokens


def _article_sentence_overlap(left: Dict[str, Any], right: Dict[str, Any]) -> float:
    def sentence_tokens(record: Dict[str, Any]) -> List[set]:
        fields = (
            "advisory_heading",
            "impact_summary",
            "report_summary",
            "recommendation",
            "source_content",
        )
        text = "\n".join(str(record.get(field) or "") for field in fields)
        text += "\n" + "\n".join(
            f"{reference.get('title', '')} {reference.get('content', '')}"
            for reference in record.get("source_references") or []
            if isinstance(reference, dict)
        )
        products = _product_names(record)
        sentences = []
        for sentence in SENTENCE_PATTERN.split(text):
            tokens = _tokens(sentence) - CONTENT_STOPWORDS
            for product in products:
                tokens.difference_update(product)
            if len(tokens) >= 5:
                sentences.append(tokens)
        return sentences

    left_sentences = sentence_tokens(left)
    right_sentences = sentence_tokens(right)
    best_score = 0.0
    for left_sentence in left_sentences:
        for right_sentence in right_sentences:
            shared = len(left_sentence & right_sentence)
            if shared < 5:
                continue
            best_score = max(
                best_score,
                shared / min(len(left_sentence), len(right_sentence)),
            )
    return best_score


def _versions(record: Dict[str, Any]) -> set:
    text = str(record.get("affected_versions") or "")
    text = re.sub(
        r"\b(?:cvss(?:\s+v\d+(?:\.\d+)?)?|score|rating)\s*(?:score)?"
        r"\s*[:=]?\s*\d+(?:\.\d+){1,4}\b",
        " ",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\b\d+(?:\.\d+){1,4}\s*%|\b\d+(?:\.\d+){1,4}\s*"
        r"(?:percent|million|billion)\b",
        " ",
        text,
        flags=re.IGNORECASE,
    )
    return {
        version.casefold().lstrip("v")
        for version in VERSION_PATTERN.findall(text)
    }


def _versions_overlap(left: set, right: set) -> bool:
    for left_version in left:
        left_parts = left_version.split(".")
        for right_version in right:
            right_parts = right_version.split(".")
            shared_length = min(len(left_parts), len(right_parts))
            if left_parts[:shared_length] == right_parts[:shared_length]:
                return True
    return False


def _vulnerability_classes(record: Dict[str, Any]) -> set:
    text = "\n".join(
        str(record.get(field) or "")
        for field in (
            "advisory_heading",
            "cve_details",
            "impact_summary",
            "report_summary",
            "source_content",
        )
    )
    return {
        label
        for label, pattern in VULNERABILITY_CLASSES
        if pattern.search(text)
    }


def _record_text(record: Dict[str, Any], fields: Iterable[str]) -> str:
    parts = [str(record.get(field) or "") for field in fields]
    for reference in record.get("source_references") or []:
        if isinstance(reference, dict):
            parts.extend(
                str(reference.get(field) or "")
                for field in ("title", "content", "impact_summary", "report_summary")
            )
    return "\n".join(parts)


def _record_entities(record: Dict[str, Any]) -> set:
    text = _record_text(
        record,
        (
            "advisory_heading",
            "matched_app_name",
            "affected_products",
            "impact_summary",
            "report_summary",
            "source_content",
            "cve_details",
        ),
    )
    entities = {match.upper() for match in CVE_PATTERN.findall(text)}
    for match in ENTITY_PATTERN.findall(text):
        normalized = " ".join(match.casefold().split())
        if normalized not in ENTITY_STOPWORDS and len(normalized) > 2:
            entities.add(normalized)
    return entities


def _semantic_text(record: Dict[str, Any]) -> str:
    return _record_text(
        record,
        ("advisory_heading", "impact_summary", "report_summary"),
    )


def _tfidf_cosine(left: str, right: str) -> float:
    left_terms = TOKEN_PATTERN.findall(str(left or "").casefold())
    right_terms = TOKEN_PATTERN.findall(str(right or "").casefold())
    left_counts = {term: left_terms.count(term) for term in set(left_terms)}
    right_counts = {term: right_terms.count(term) for term in set(right_terms)}
    terms = set(left_counts) | set(right_counts)
    if not terms:
        return 0.0
    left_vector = {}
    right_vector = {}
    for term in terms:
        document_frequency = int(term in left_counts) + int(term in right_counts)
        inverse_frequency = math.log(3 / (document_frequency + 1)) + 1
        left_vector[term] = left_counts.get(term, 0) * inverse_frequency
        right_vector[term] = right_counts.get(term, 0) * inverse_frequency
    dot_product = sum(left_vector[term] * right_vector[term] for term in terms)
    left_norm = math.sqrt(sum(value * value for value in left_vector.values()))
    right_norm = math.sqrt(sum(value * value for value in right_vector.values()))
    return dot_product / (left_norm * right_norm) if left_norm and right_norm else 0.0


def _lifecycle_stages(record: Dict[str, Any]) -> set:
    text = _record_text(
        record,
        ("advisory_heading", "impact_summary", "report_summary", "source_content"),
    )
    return {
        stage
        for stage, pattern in LIFECYCLE_PATTERNS.items()
        if pattern.search(text)
    }


def _comparison(
    left: Dict[str, Any],
    right: Dict[str, Any],
    candidate_threshold: float = 0.18,
) -> Tuple[Optional[str], float]:
    if left.get("id") and str(left["id"]) == str(right.get("id") or ""):
        return "duplicate", 1.0

    product_score = _product_similarity(left, right)
    left_cves = _record_cves(left)
    right_cves = _record_cves(right)
    shared_cves = left_cves & right_cves
    if left_cves and right_cves and not shared_cves:
        return None, 0.0

    shared_entities = _record_entities(left) & _record_entities(right)
    semantic_score = _tfidf_cosine(_semantic_text(left), _semantic_text(right))
    left_stages = _lifecycle_stages(left)
    right_stages = _lifecycle_stages(right)
    lifecycle_conflict = bool(
        left_stages and right_stages and not left_stages.intersection(right_stages)
    )
    if product_score < 0.5:
        if shared_entities and (
            semantic_score >= candidate_threshold
            or bool(shared_cves) and semantic_score >= candidate_threshold / 2
        ):
            return "possible", semantic_score
        return None, 0.0

    left_versions = _versions(left)
    right_versions = _versions(right)
    version_conflict = bool(
        left_versions
        and right_versions
        and not _versions_overlap(left_versions, right_versions)
    )
    left_classes = _vulnerability_classes(left)
    right_classes = _vulnerability_classes(right)
    shared_classes = left_classes & right_classes
    class_conflict = bool(
        left_classes and right_classes and not shared_classes
    )
    title_score = _similarity(_title_tokens(left), _title_tokens(right))

    if lifecycle_conflict:
        if shared_cves or shared_entities and semantic_score >= candidate_threshold:
            return "possible", max(title_score, semantic_score)

    if shared_cves:
        primary_cves_match = bool(_primary_cves(left) & _primary_cves(right))
        if primary_cves_match and not version_conflict and not class_conflict:
            return "duplicate", 1.0
        if primary_cves_match and (version_conflict or class_conflict):
            return "possible", 0.75
        if title_score < 0.3 or version_conflict or class_conflict:
            return None, 0.0
        article_score = _similarity(_article_tokens(left), _article_tokens(right))
        if article_score >= 0.25:
            return "duplicate", (
                0.25 * product_score + 0.3 * title_score + 0.45 * article_score
            )
        sentence_score = _article_sentence_overlap(left, right)
        if (
            not version_conflict
            and not class_conflict
            and sentence_score >= 0.7
        ):
            return "duplicate", (
                0.25 * product_score
                + 0.3 * title_score
                + 0.45 * sentence_score
            )
        return None, 0.0

    same_class = bool(shared_classes)
    article_score = _similarity(_article_tokens(left), _article_tokens(right))
    if not version_conflict and not class_conflict and (
        (same_class and article_score >= 0.25)
        or (title_score >= 0.55 and article_score >= 0.15)
    ):
        score = (
            0.25 * product_score
            + 0.3 * title_score
            + 0.45 * article_score
        )
        return "duplicate", score
    sentence_score = _article_sentence_overlap(left, right)
    if (
        not version_conflict
        and not class_conflict
        and (
            (same_class and sentence_score >= 0.7)
            or (title_score >= 0.55 and sentence_score >= 0.7)
        )
    ):
        return "duplicate", (
            0.25 * product_score + 0.3 * title_score + 0.45 * sentence_score
        )
    if (
        not class_conflict
        and (title_score >= 0.25 or article_score >= 0.3 or sentence_score >= 0.65)
        and (same_class or not left_classes or not right_classes)
    ):
        return "possible", 0.5 * title_score + 0.5 * max(article_score, sentence_score)
    return None, 0.0


def _merge_unique_sentences(
    primary: Any,
    additional: Any,
    excluded: Iterable[Any] = (),
) -> str:
    sentences = []
    excluded_tokens = [
        (_tokens(sentence), _sentence_identifiers(sentence))
        for value in excluded
        for sentence in SENTENCE_PATTERN.split(str(value or ""))
        if sentence.strip()
    ]

    for value in (primary, additional):
        for sentence in SENTENCE_PATTERN.split(str(value or "")):
            sentence = sentence.strip()
            tokens = _tokens(sentence)
            if not sentence or not tokens:
                continue
            identifiers = _sentence_identifiers(sentence)
            if any(
                _sentence_similarity(tokens, excluded_set) >= 0.85
                and len(tokens & excluded_set) >= 2
                and abs(len(tokens) - len(excluded_set))
                <= max(2, int(0.25 * max(len(tokens), len(excluded_set))))
                and identifiers.issubset(excluded_identifiers)
                for excluded_set, excluded_identifiers in excluded_tokens
            ):
                continue
            matching = next(
                (
                    index for index, existing in enumerate(sentences)
                    if _sentence_similarity(tokens, _tokens(existing)) >= 0.85
                    and len(tokens & _tokens(existing)) >= 2
                    and abs(len(tokens) - len(_tokens(existing)))
                    <= max(2, int(0.25 * max(len(tokens), len(_tokens(existing)))))
                    and identifiers == _sentence_identifiers(existing)
                ),
                None,
            )
            if matching is not None:
                if len(tokens) > len(_tokens(sentences[matching])):
                    sentences[matching] = sentence
                continue
            sentences.append(sentence)
    return " ".join(sentences)


def _source_references(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    source_items = record.get("source_references")
    if not isinstance(source_items, list) or not source_items:
        source_items = [{
            "article_id": record.get("id", ""),
            "source_name": record.get("source_name", ""),
            "link": record.get("link", ""),
            "title": record.get("advisory_heading", ""),
            "content": record.get("source_content", ""),
            "impact_summary": record.get("impact_summary", ""),
            "report_summary": record.get("report_summary", ""),
            "recommendation": record.get("recommendation", ""),
            "affected_products": record.get("affected_products", ""),
            "affected_versions": record.get("affected_versions", ""),
            "severity": record.get("severity", ""),
            "published_timestamp": record.get("published_timestamp", ""),
            "cve_details": record.get("cve_details", ""),
            "iocs": record.get("iocs", ""),
        }]

    references = []
    seen = set()
    for reference in source_items:
        if not isinstance(reference, dict):
            continue
        source_name = str(reference.get("source_name") or "").strip()
        link = str(reference.get("link") or "").strip()
        title = str(reference.get("title") or "").strip()
        article_id = str(reference.get("article_id") or reference.get("id") or "").strip()
        key = ("id", article_id.casefold()) if article_id else (
            ("link", link.casefold()) if link else (
            "source", source_name.casefold(), title.casefold()
            )
        )
        if key in seen or not source_name and not link and not title:
            continue
        seen.add(key)
        clean_reference = {
            "article_id": article_id,
            "source_name": source_name,
            "link": link,
            "title": title,
        }
        for field in (
            "content",
            "impact_summary",
            "report_summary",
            "recommendation",
            "affected_products",
            "affected_versions",
            "severity",
            "published_timestamp",
            "cve_details",
            "iocs",
        ):
            value = reference.get(field)
            if value not in (None, ""):
                clean_reference[field] = value
        references.append(clean_reference)
    return references


def _append_references(target: Dict[str, Any], incoming: Dict[str, Any]) -> None:
    references = _source_references(target)
    seen = {
        ("id", str(item.get("article_id") or "").casefold())
        if item.get("article_id")
        else (("link", item["link"].casefold()) if item["link"] else (
            "source", item["source_name"].casefold(), item["title"].casefold()
        ))
        for item in references
    }
    for reference in _source_references(incoming):
        key = ("id", str(reference.get("article_id") or "").casefold()) \
            if reference.get("article_id") else (
                ("link", reference["link"].casefold()) if reference["link"] else (
                    "source", reference["source_name"].casefold(), reference["title"].casefold()
                )
            )
        if key not in seen:
            references.append(reference)
            seen.add(key)
    target["source_references"] = references


def _merge_source_content(target: Dict[str, Any], incoming: Dict[str, Any]) -> None:
    sources = []
    seen = set()
    for record in (target, incoming):
        content = str(record.get("source_content") or "").strip()
        if not content:
            continue
        sections = re.split(r"(?m)^\[([^\]\n]+)\]\s*\n", content)
        if len(sections) > 1:
            source_sections = [
                (sections[index], sections[index + 1].strip())
                for index in range(1, len(sections) - 1, 2)
            ]
        else:
            source_sections = [
                (str(record.get("source_name") or "Source").strip(), content)
            ]
        for source_name, source_text in source_sections:
            key = " ".join(source_text.casefold().split())
            if not key or key in seen:
                continue
            seen.add(key)
            sources.append(f"[{source_name}]\n{source_text}")
    if sources:
        target["source_content"] = "\n\n".join(sources)


def _merge_advisory(target: Dict[str, Any], incoming: Dict[str, Any]) -> None:
    conflicts = target.setdefault("summary_conflicts", [])
    for conflict in _record_conflicts(target, incoming):
        if conflict not in conflicts:
            conflicts.append(conflict)
    if conflicts:
        target["report_summary"] = _merge_unique_sentences(
            target.get("report_summary"),
            " ".join(conflicts),
        )

    prior_text = "\n".join(
        str(target.get(field) or "")
        for field in ("impact_summary", "report_summary", "recommendation")
    )
    incoming_text = "\n".join(
        str(incoming.get(field) or "")
        for field in ("impact_summary", "report_summary", "recommendation")
    )
    new_information = _merge_unique_sentences(
        "",
        incoming_text,
        excluded=(prior_text,),
    )
    for field, label in (
        ("cve_details", "New CVEs"),
        ("affected_products", "New affected products"),
        ("affected_versions", "New affected versions"),
        ("iocs", "New IOCs"),
    ):
        existing_values = {
            item.strip().casefold()
            for item in re.split(r"[;,\n]+", str(target.get(field) or ""))
            if item.strip()
        }
        added_values = [
            item.strip()
            for item in re.split(r"[;,\n]+", str(incoming.get(field) or ""))
            if item.strip()
            and item.strip().casefold() not in existing_values
            and item.strip().casefold() not in {"na", "n/a", "none", "unknown"}
        ]
        if added_values:
            new_information = _merge_unique_sentences(
                new_information,
                f"{label}: {', '.join(added_values)}.",
            )
    if new_information:
        updates = target.setdefault("_new_source_information", [])
        if new_information not in updates:
            updates.append(new_information)

    cves = list(dict.fromkeys(
        match.upper()
        for value in (target.get("cve_details"), incoming.get("cve_details"))
        for match in CVE_PATTERN.findall(str(value or ""))
    ))
    if cves:
        target["cve_details"] = ", ".join(cves)

    target["impact_summary"] = _merge_unique_sentences(
        target.get("impact_summary"),
        incoming.get("impact_summary"),
    )
    target["report_summary"] = _merge_unique_sentences(
        target.get("report_summary"),
        incoming.get("report_summary"),
        excluded=(target["impact_summary"],),
    )
    target["recommendation"] = _merge_unique_sentences(
        target.get("recommendation"),
        incoming.get("recommendation"),
    )
    for field in ("affected_products", "affected_versions"):
        values = []
        seen = set()
        for value in (target.get(field), incoming.get(field)):
            for item in re.split(r"[;\n]+", str(value or "")):
                item = item.strip()
                key = item.casefold()
                if key and key not in {"na", "n/a", "none", "unknown"} and key not in seen:
                    values.append(item)
                    seen.add(key)
        if values:
            target[field] = "; ".join(values)
    for field in ("iocs", "matched_app_name"):
        values = []
        seen = set()
        for value in (target.get(field), incoming.get(field)):
            for item in re.split(r"[,;\n]+", str(value or "")):
                item = item.strip()
                key = item.casefold()
                if key and key not in {"na", "n/a", "none", "unknown"} and key not in seen:
                    values.append(item)
                    seen.add(key)
        if values:
            target[field] = "; ".join(values)

    left_metrics = target.get("cve_metrics")
    right_metrics = incoming.get("cve_metrics")
    if isinstance(left_metrics, dict) and isinstance(right_metrics, dict):
        merged_metrics = dict(left_metrics)
        for cve, metrics in right_metrics.items():
            if cve not in merged_metrics:
                merged_metrics[cve] = metrics
            elif isinstance(metrics, dict) and isinstance(merged_metrics[cve], dict):
                merged_metrics[cve] = {
                    **metrics,
                    **{
                        key: value
                        for key, value in merged_metrics[cve].items()
                        if str(value or "").strip().casefold()
                        not in {"", "na", "n/a", "not available"}
                    },
                }
        target["cve_metrics"] = merged_metrics

    _merge_source_content(target, incoming)
    _append_references(target, incoming)
    article_ids = target.setdefault("_deduplicated_article_ids", [])
    for article_id in [
        incoming.get("id"),
        *incoming.get("_deduplicated_article_ids", []),
    ]:
        if article_id and article_id != target.get("id") and article_id not in article_ids:
            article_ids.append(article_id)
    members = target.setdefault(
        "member_article_ids",
        [value for value in (target.get("id"),) if value],
    )
    for article_id in (
        incoming.get("id"),
        *(incoming.get("member_article_ids") or []),
        *(incoming.get("_deduplicated_article_ids") or []),
    ):
        if article_id and article_id not in members:
            members.append(article_id)
    target["duplicate_candidate_ids"] = [
        article_id
        for article_id in members
        if article_id != str(target.get("id") or "")
    ]


def _stable_advisory_id(record: Dict[str, Any]) -> str:
    existing = str(record.get("advisory_id") or "").strip()
    if existing:
        return existing
    seed = str(
        record.get("id")
        or record.get("link")
        or record.get("advisory_heading")
        or "unknown-advisory"
    ).strip().casefold()
    return "ADV-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:20].upper()


def _member_ids(record: Dict[str, Any]) -> List[str]:
    values = [
        record.get("id"),
        *(record.get("member_article_ids") or []),
        *(record.get("_deduplicated_article_ids") or []),
    ]
    return list(dict.fromkeys(str(value).strip() for value in values if str(value or "").strip()))


def _pair_key(left_id: str, right_id: str) -> Tuple[str, str]:
    return tuple(sorted((str(left_id), str(right_id))))


def _record_conflicts(left: Dict[str, Any], right: Dict[str, Any]) -> List[str]:
    conflicts = []
    left_versions = str(left.get("affected_versions") or "").strip()
    right_versions = str(right.get("affected_versions") or "").strip()
    if (
        left_versions
        and right_versions
        and left_versions.casefold() not in {"na", "n/a", "unknown"}
        and right_versions.casefold() not in {"na", "n/a", "unknown"}
        and not _versions_overlap(_versions(left), _versions(right))
    ):
        conflicts.append(
            "Sources report different affected versions: "
            f"{left.get('source_name') or 'Source 1'} reports {left_versions}; "
            f"{right.get('source_name') or 'Source 2'} reports {right_versions}."
        )
    left_severity = str(left.get("severity") or "").strip().upper()
    right_severity = str(right.get("severity") or "").strip().upper()
    known_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    if (
        left_severity in known_severities
        and right_severity in known_severities
        and left_severity != right_severity
    ):
        conflicts.append(
            "Sources assign different severities: "
            f"{left.get('source_name') or 'Source 1'} reports {left_severity}; "
            f"{right.get('source_name') or 'Source 2'} reports {right_severity}."
        )
    return conflicts


def _flag_possible_duplicate(
    record: Dict[str, Any],
    matches: Iterable[Dict[str, Any]],
) -> None:
    matches = list(matches)
    titles = []
    for match in matches:
        heading = str(match.get("advisory_heading") or "existing advisory").strip()
        if heading not in titles:
            titles.append(heading)
    if titles:
        note = (
            "Possible duplicate of "
            + "; ".join(titles[:2])
            + ". Compare the source details; set Duplicate Check to "
            "'Same Event' or 'Keep Separate' to remember the decision."
        )
        lifecycle_notes = []
        for match in matches:
            left_stages = _lifecycle_stages(record)
            right_stages = _lifecycle_stages(match)
            if left_stages and right_stages and not left_stages.intersection(right_stages):
                lifecycle_notes.append(
                    "Different lifecycle stages ("
                    + ", ".join(sorted(left_stages))
                    + " vs "
                    + ", ".join(sorted(right_stages))
                    + "); keep separate and cross-reference "
                    + str(match.get("advisory_heading") or "the related advisory")
                    + (f" at {match.get('link')}" if match.get("link") else "")
                    + "."
                )
        if lifecycle_notes:
            note += " " + " ".join(dict.fromkeys(lifecycle_notes))
        record["duplicate_note"] = note
        own_ids = set(_member_ids(record))
        record["duplicate_candidate_ids"] = list(dict.fromkeys(
            article_id
            for match in matches
            for article_id in _member_ids(match)
            if article_id not in own_ids
        ))
        existing_note = str(record.get("triage_note") or "").strip()
        record["triage_note"] = "; ".join(
            item for item in (existing_note, note) if item
        )
        record["initial_triage"] = "Flagged"
        record["review_decision"] = "☐ Pending"


class AdvisoryDeduplicator:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.proposals: List[Dict[str, Any]] = []

    def deduplicate(
        self,
        records: List[Dict[str, Any]],
        archived_records: List[Dict[str, Any]],
        *,
        pending_records: Optional[List[Dict[str, Any]]] = None,
        pair_decisions: Optional[Dict[Tuple[str, str], Dict[str, Any]]] = None,
        decision_callback: Optional[Callable[..., None]] = None,
        adjudicator: Optional[Callable[[Dict[str, Any], Dict[str, Any]], Optional[Dict[str, Any]]]] = None,
        summarizer: Optional[Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]] = None,
        same_event_threshold: float = 0.85,
        candidate_threshold: float = 0.18,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]:
        consolidated: List[Dict[str, Any]] = []
        archive_updates: Dict[str, List[Dict[str, Any]]] = {}
        pending_records = pending_records or []
        pair_decisions = pair_decisions or {}
        changed_records: List[Dict[str, Any]] = []
        self.proposals = []
        for archived in archived_records:
            archived.setdefault("source_references", _source_references(archived))
            archived.setdefault("_deduplicated_article_ids", [])
            archived.setdefault("member_article_ids", _member_ids(archived))
            archived["advisory_id"] = _stable_advisory_id(archived)
        for pending in pending_records:
            pending.setdefault("source_references", _source_references(pending))
            pending.setdefault("_deduplicated_article_ids", [])
            pending.setdefault("member_article_ids", _member_ids(pending))
            pending["advisory_id"] = _stable_advisory_id(pending)

        for record in records:
            record["source_references"] = _source_references(record)
            record.setdefault("_deduplicated_article_ids", [])
            record.setdefault("member_article_ids", _member_ids(record))
            record["advisory_id"] = _stable_advisory_id(record)
            candidates = [
                (existing, True)
                for existing in archived_records
            ] + [
                (existing, False)
                for existing in pending_records
            ] + [
                (existing, False)
                for existing in consolidated
            ]
            comparisons = []
            for existing, is_archived in candidates:
                pair_keys = [
                    _pair_key(new_id, existing_id)
                    for new_id in _member_ids(record)
                    for existing_id in _member_ids(existing)
                    if new_id != existing_id
                ]
                remembered = [
                    pair_decisions[key]
                    for key in pair_keys
                    if key in pair_decisions
                ]
                left_stages = _lifecycle_stages(record)
                right_stages = _lifecycle_stages(existing)
                lifecycle_conflict = bool(
                    left_stages
                    and right_stages
                    and not left_stages.intersection(right_stages)
                )
                if any(not item.get("same_event") for item in remembered):
                    self._log_decision(
                        record,
                        existing,
                        "kept_separate",
                        1.0,
                        "Previously recorded pair decision.",
                    )
                    continue
                if remembered and any(item.get("same_event") for item in remembered):
                    if lifecycle_conflict:
                        heading = str(
                            existing.get("advisory_heading") or "the related advisory"
                        )
                        link = str(existing.get("link") or "").strip()
                        record["duplicate_note"] = (
                            "Previously decided as related, but lifecycle stages differ ("
                            + ", ".join(sorted(left_stages))
                            + " vs "
                            + ", ".join(sorted(right_stages))
                            + "); keep separate and cross-reference "
                            + heading
                            + (f" at {link}" if link else "")
                            + "."
                        )
                        record["duplicate_candidate_ids"] = _member_ids(existing)
                        self._log_decision(
                            record,
                            existing,
                            "kept_separate_lifecycle",
                            1.0,
                            record["duplicate_note"],
                        )
                        continue
                    status, score = "duplicate", 1.0
                else:
                    status, score = _comparison(
                        record,
                        existing,
                        candidate_threshold=candidate_threshold,
                    )
                if status:
                    comparisons.append((
                        status,
                        score,
                        existing,
                        is_archived,
                        pair_keys,
                        bool(remembered),
                    ))

            possible = [item for item in comparisons if item[0] == "possible"]
            adjudicated = []
            for item in possible:
                status, score, existing, is_archived, pair_keys, remembered = item
                result = adjudicator(record, existing) if adjudicator else None
                confidence = (
                    float(result.get("confidence", 0))
                    if isinstance(result, dict)
                    and isinstance(result.get("confidence"), (int, float))
                    and not isinstance(result.get("confidence"), bool)
                    else 0.0
                )
                same_event = (
                    result.get("same_event")
                    if isinstance(result, dict)
                    and isinstance(result.get("same_event"), bool)
                    else None
                )
                reason = (
                    str(result.get("reason") or "")
                    if isinstance(result, dict)
                    else "LLM adjudication unavailable; retained for human review."
                )
                if lifecycle_conflict:
                    _flag_possible_duplicate(record, [existing])
                if same_event is not None and confidence >= same_event_threshold:
                    if lifecycle_conflict:
                        reason = (
                            f"Lifecycle stages differ ({', '.join(sorted(left_stages))} vs "
                            f"{', '.join(sorted(right_stages))}); retained separately. "
                            + reason
                        )
                        self._record_decisions(
                            record,
                            existing,
                            pair_keys,
                            False,
                            reason,
                            confidence,
                            decision_callback,
                        )
                        self._log_decision(
                            record, existing, "kept_separate_lifecycle", confidence, reason
                        )
                        continue
                    if same_event:
                        adjudicated.append((
                            "duplicate",
                            confidence,
                            existing,
                            is_archived,
                            pair_keys,
                            True,
                        ))
                        self._log_decision(
                            record,
                            existing,
                            "llm_same_event",
                            confidence,
                            reason,
                        )
                        self._record_decisions(
                            record,
                            existing,
                            pair_keys,
                            True,
                            reason,
                            confidence,
                            decision_callback,
                        )
                    else:
                        self._record_decisions(
                            record,
                            existing,
                            pair_keys,
                            False,
                            reason,
                            confidence,
                            decision_callback,
                        )
                        self._log_decision(
                            record, existing, "kept_separate_llm", confidence, reason
                        )
                    continue
                adjudicated.append(item)
                self._log_decision(
                    record,
                    existing,
                    "pending_review",
                    score,
                    reason,
                )

            confident = [
                item for item in comparisons + adjudicated
                if item[0] == "duplicate"
            ]
            confident = list({id(item[2]): item for item in confident}.values())
            if confident:
                _, best_score, canonical, is_archived, pair_keys, _ = max(
                    confident,
                    key=lambda item: (item[3], item[1]),
                )
                for _, score, existing, existing_is_archived, matched_pairs, _ in confident:
                    if existing is canonical or existing_is_archived:
                        continue
                    _merge_advisory(canonical, existing)
                    changed_records.append(canonical)
                    if existing.get("_pending_daily_path"):
                        existing["_pending_daily_updated"] = True
                        existing["_pending_archive_merged"] = True
                        existing["review_decision"] = "Previously Reported"
                        existing["duplicate_note"] = (
                            f"Merged into advisory {canonical.get('advisory_id')}."
                        )
                    self._record_decisions(
                        record,
                        existing,
                        matched_pairs,
                        True,
                        "High-confidence heuristic match.",
                        score,
                        decision_callback,
                    )
                    consolidated = [
                        item for item in consolidated if item is not existing
                    ]
                _merge_advisory(canonical, record)
                changed_records.append(canonical)
                if canonical.get("_pending_daily_path"):
                    canonical["_pending_daily_updated"] = True
                self._record_decisions(
                    record,
                    canonical,
                    pair_keys,
                    True,
                    "Merged as the same underlying event.",
                    best_score,
                    decision_callback,
                )
                self._log_decision(
                    record,
                    canonical,
                    "merged",
                    best_score,
                    "Same underlying event.",
                )
                if is_archived:
                    group = str(canonical.get("_archive_group") or "")
                    if group:
                        updates = archive_updates.setdefault(group, [])
                        if all(item is not canonical for item in updates):
                            updates.append(canonical)
                continue

            remaining_possible = [
                item for item in adjudicated
                if item[0] == "possible"
            ]
            if remaining_possible:
                ranked = sorted(remaining_possible, key=lambda item: item[1], reverse=True)
                _flag_possible_duplicate(
                    record,
                    (item[2] for item in ranked),
                )
            consolidated.append(record)

        for pending in pending_records:
            if not pending.get("_pending_daily_updated", False):
                if str(pending.get("_pending_daily_date") or "") == str(
                    pending.get("_today_date") or ""
                ):
                    pending["_dedupe_group"] = pending.get(
                        "_pending_daily_group",
                        "miscellaneous",
                    )
                    if all(item is not pending for item in consolidated):
                        consolidated.append(pending)
                continue
            if pending.get("_pending_archive_merged"):
                continue
            changed_records.append(pending)
            pending_date = str(pending.get("_pending_daily_date") or "")
            today = str(pending.get("_today_date") or "")
            if pending_date and today and pending_date < today:
                current_decision = pending.get("_pending_review_decision", "☐ Pending")
                moved = deepcopy(pending)
                for key in (
                    "_pending_daily_group",
                    "_pending_daily_path",
                    "_pending_daily_date",
                    "_today_date",
                    "_pending_daily_updated",
                    "_pending_review_decision",
                ):
                    moved.pop(key, None)
                moved["review_decision"] = current_decision
                moved["_dedupe_group"] = pending.get("_pending_daily_group", "miscellaneous")
                consolidated.append(moved)
                pending["review_decision"] = "Previously Reported"
                pending["duplicate_note"] = (
                    f"Merged into advisory {pending.get('advisory_id')} and moved to "
                    f"the {today} review workbook."
                )
                pending.pop("_today_date", None)
            else:
                pending["_dedupe_group"] = pending.get(
                    "_pending_daily_group",
                    "miscellaneous",
                )
                consolidated.append(pending)

        if summarizer:
            for record in dict.fromkeys(id(item) for item in changed_records):
                target = next(item for item in changed_records if id(item) == record)
                summary = summarizer(target)
                if not isinstance(summary, dict):
                    continue
                for field in (
                    "impact_summary",
                    "report_summary",
                    "recommendation",
                    "affected_products",
                    "affected_versions",
                    "severity",
                    "cve_details",
                    "iocs",
                ):
                    value = summary.get(field)
                    if isinstance(value, str) and value.strip():
                        target[field] = value.strip()
                conflicts = target.setdefault("summary_conflicts", [])
                for conflict in summary.get("conflicts", []):
                    if isinstance(conflict, str) and conflict.strip() and conflict not in conflicts:
                        conflicts.append(conflict.strip())
                if conflicts:
                    target["report_summary"] = _merge_unique_sentences(
                        target.get("report_summary"),
                        " ".join(conflicts),
                    )

        return consolidated, archive_updates

    def _record_decisions(
        self,
        left: Dict[str, Any],
        right: Dict[str, Any],
        pair_keys: Iterable[Tuple[str, str]],
        same_event: bool,
        reason: str,
        confidence: float,
        callback: Optional[Callable[..., None]],
    ) -> None:
        if not callback:
            return
        left_ids = set(_member_ids(left))
        right_ids = set(_member_ids(right))
        for left_id, right_id in pair_keys:
            if (
                left_id not in left_ids | right_ids
                or right_id not in left_ids | right_ids
                or left_id == right_id
            ):
                continue
            callback(
                left_id,
                right_id,
                same_event=same_event,
                decided_by="auto",
                reason=reason,
                confidence=confidence,
            )

    def _log_decision(
        self,
        left: Dict[str, Any],
        right: Dict[str, Any],
        decision: str,
        score: float,
        reason: str,
    ) -> None:
        left_id = str(left.get("id") or left.get("advisory_id") or "")
        right_id = str(right.get("id") or right.get("advisory_id") or "")
        entry = {
            "left_id": left_id,
            "right_id": right_id,
            "decision": decision,
            "score": round(float(score), 4),
            "reason": reason,
        }
        self.proposals.append(entry)
        self.logger.info(
            "Advisory merge decision: left_id=%s right_id=%s decision=%s score=%.4f reason=%s",
            left_id,
            right_id,
            decision,
            float(score),
            reason,
        )


def split_advisory_cluster(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    references = _source_references(record)
    if len(references) < 2:
        return []
    split_records = []
    for reference in references:
        article_id = str(reference.get("article_id") or "").strip()
        if not article_id:
            continue
        member = deepcopy(record)
        member.update({
            "id": article_id,
            "source_name": reference.get("source_name") or record.get("source_name", ""),
            "link": reference.get("link") or "",
            "advisory_heading": reference.get("title") or record.get("advisory_heading", ""),
            "source_content": reference.get("content") or "",
            "impact_summary": reference.get("impact_summary") or "",
            "report_summary": reference.get("report_summary") or "",
            "recommendation": reference.get("recommendation") or "",
            "affected_products": reference.get("affected_products") or "",
            "affected_versions": reference.get("affected_versions") or "",
            "severity": reference.get("severity") or record.get("severity", ""),
            "published_timestamp": reference.get("published_timestamp") or record.get("published_timestamp", ""),
            "cve_details": reference.get("cve_details") or record.get("cve_details", ""),
            "iocs": reference.get("iocs") or "",
            "source_references": [reference],
            "member_article_ids": [article_id],
            "_deduplicated_article_ids": [],
            "advisory_id": _stable_advisory_id({"id": article_id}),
            "duplicate_note": "",
            "duplicate_candidate_ids": [],
            "review_decision": "☐ Pending",
        })
        split_records.append(member)
    return split_records
