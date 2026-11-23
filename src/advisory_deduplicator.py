import re
from typing import Any, Dict, Iterable, List, Optional, Tuple


CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
TOKEN_PATTERN = re.compile(r"[a-z0-9]+")
SENTENCE_PATTERN = re.compile(r"(?<=[.!?])\s+|\n+")
VERSION_PATTERN = re.compile(r"\bv?\d+(?:\.\d+){1,4}\b", re.IGNORECASE)
STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "by", "can", "for", "from",
    "in", "is", "it", "its", "of", "on", "or", "that", "the", "this",
    "to", "was", "with", "security", "advisory", "vulnerability",
    "vulnerabilities", "issue", "issues", "flaw", "flaws", "affects",
    "affecting", "allow", "allows", "attackers", "attacker", "remote",
    "unauthenticated", "versions", "version", "multiple", "source",
}
CONTENT_STOPWORDS = STOPWORDS | {
    "affected", "attack", "base", "bugs", "check", "critical", "execute",
    "execution", "fix", "fixes", "guidance", "identified", "patch",
    "patches", "review", "score", "update", "updates", "vendor",
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


def _comparison(
    left: Dict[str, Any],
    right: Dict[str, Any],
) -> Tuple[Optional[str], float]:
    if left.get("id") and str(left["id"]) == str(right.get("id") or ""):
        return "duplicate", 1.0

    product_score = _product_similarity(left, right)
    if product_score < 0.5:
        return None, 0.0

    left_cves = _record_cves(left)
    right_cves = _record_cves(right)
    shared_cves = left_cves & right_cves
    if left_cves and right_cves and not shared_cves:
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


def _source_references(record: Dict[str, Any]) -> List[Dict[str, str]]:
    source_items = record.get("source_references")
    if not isinstance(source_items, list) or not source_items:
        source_items = [{
            "source_name": record.get("source_name", ""),
            "link": record.get("link", ""),
            "title": record.get("advisory_heading", ""),
        }]

    references = []
    seen = set()
    for reference in source_items:
        if not isinstance(reference, dict):
            continue
        source_name = str(reference.get("source_name") or "").strip()
        link = str(reference.get("link") or "").strip()
        title = str(reference.get("title") or "").strip()
        key = ("link", link.casefold()) if link else (
            "source", source_name.casefold(), title.casefold()
        )
        if key in seen or not source_name and not link and not title:
            continue
        seen.add(key)
        clean_reference = {
            "source_name": source_name,
            "link": link,
            "title": title,
        }
        content = str(reference.get("content") or "").strip()
        if content:
            clean_reference["content"] = content
        references.append(clean_reference)
    return references


def _append_references(target: Dict[str, Any], incoming: Dict[str, Any]) -> None:
    references = _source_references(target)
    seen = {
        ("link", item["link"].casefold()) if item["link"] else (
            "source", item["source_name"].casefold(), item["title"].casefold()
        )
        for item in references
    }
    for reference in _source_references(incoming):
        key = ("link", reference["link"].casefold()) if reference["link"] else (
            "source", reference["source_name"].casefold(), reference["title"].casefold()
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


def _flag_possible_duplicate(
    record: Dict[str, Any],
    matches: Iterable[Dict[str, Any]],
) -> None:
    titles = []
    for match in matches:
        heading = str(match.get("advisory_heading") or "existing advisory").strip()
        if heading not in titles:
            titles.append(heading)
    if titles:
        note = (
            "Possible duplicate of "
            + "; ".join(titles[:2])
            + ". Compare the title, product, affected versions, and technical details."
        )
        record["duplicate_note"] = note
        existing_note = str(record.get("triage_note") or "").strip()
        record["triage_note"] = "; ".join(
            item for item in (existing_note, note) if item
        )
        record["initial_triage"] = "Flagged"
        record["review_decision"] = "☐ Pending"


class AdvisoryDeduplicator:
    def deduplicate(
        self,
        records: List[Dict[str, Any]],
        archived_records: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]:
        consolidated = []
        archive_updates: Dict[str, List[Dict[str, Any]]] = {}
        for archived in archived_records:
            archived.setdefault("source_references", _source_references(archived))
            archived.setdefault("_deduplicated_article_ids", [])

        for record in records:
            record["source_references"] = _source_references(record)
            record.setdefault("_deduplicated_article_ids", [])
            candidates = [
                (existing, True)
                for existing in archived_records
            ] + [
                (existing, False)
                for existing in consolidated
            ]
            comparisons = []
            for existing, is_archived in candidates:
                status, score = _comparison(record, existing)
                if status:
                    comparisons.append((status, score, existing, is_archived))

            confident = [item for item in comparisons if item[0] == "duplicate"]
            if confident:
                _, _, canonical, is_archived = max(
                    confident,
                    key=lambda item: (item[3], item[1]),
                )
                for _, _, existing, existing_is_archived in confident:
                    if existing is canonical or existing_is_archived:
                        continue
                    _merge_advisory(canonical, existing)
                    consolidated = [
                        item for item in consolidated if item is not existing
                    ]
                _merge_advisory(canonical, record)
                if is_archived:
                    group = str(canonical.get("_archive_group") or "")
                    if group:
                        updates = archive_updates.setdefault(group, [])
                        if all(item is not canonical for item in updates):
                            updates.append(canonical)
                continue

            possible = [item for item in comparisons if item[0] == "possible"]
            if possible:
                ranked = sorted(possible, key=lambda item: item[1], reverse=True)
                _flag_possible_duplicate(
                    record,
                    (item[2] for item in ranked),
                )
            consolidated.append(record)

        return consolidated, archive_updates
