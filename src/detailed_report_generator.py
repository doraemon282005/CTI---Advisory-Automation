import hashlib
import logging
import re
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.opc.constants import RELATIONSHIP_TYPE
from docx.table import Table
from docx.text.paragraph import Paragraph


_EMPTY_VALUES = {"", "na", "n/a", "none", "not available", "unknown"}
_GENERIC_RECOMMENDATION = (
    "No remediation guidance was identified in the advisory or Tenable data. "
    "Consult the linked vendor advisory for remediation instructions."
)
_IOC_LABELS = {
    "domain", "email", "file", "filename", "hash", "hostname", "ip", "ipv4",
    "ipv6", "md5", "sha1", "sha256", "url", "user-agent",
}
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def _known_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if text.casefold() in _EMPTY_VALUES:
        return ""
    if text.casefold() == _GENERIC_RECOMMENDATION.casefold():
        return ""
    return text


def _safe_filename(value: str) -> str:
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", value)
    cleaned = re.sub(r"\s+", "_", cleaned).strip(" ._")
    return cleaned[:100] or "advisory"


def _source_records(record: Dict[str, Any]) -> List[Dict[str, str]]:
    references = record.get("source_references")
    sources = []
    seen = set()
    if isinstance(references, list):
        for reference in references:
            if not isinstance(reference, dict):
                continue
            name = _known_text(reference.get("source_name")) or "Source"
            link = _known_text(reference.get("link"))
            published = _format_timestamp(reference.get("published_timestamp"))
            key = link or f"{name.casefold()}|{published}"
            if key in seen:
                continue
            seen.add(key)
            sources.append({
                "name": name,
                "title": _known_text(reference.get("title")),
                "link": link,
                "published": published,
            })
    if not sources:
        sources.append({
            "name": _known_text(record.get("source_name")) or "Source",
            "title": _known_text(record.get("advisory_heading")),
            "link": _known_text(record.get("link")),
            "published": _format_timestamp(record.get("published_timestamp")),
        })
    return sources


def _format_timestamp(value: Any) -> str:
    if isinstance(value, (int, float)):
        if value > 0:
            return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M")
        return ""
    return _known_text(value)


def _is_newsletter_digest(record: Dict[str, Any]) -> bool:
    titles = [str(record.get("advisory_heading") or "")]
    references = record.get("source_references")
    if isinstance(references, list):
        titles.extend(
            str(reference.get("title") or "")
            for reference in references
            if isinstance(reference, dict)
        )
    return any(
        re.search(r"\b(?:newsletter|round[- ]?up|weekly digest)\b", title, re.I)
        for title in titles
    )


def _source_evidence(record: Dict[str, Any]) -> str:
    pieces = [str(record.get("advisory_heading") or "")]
    references = record.get("source_references")
    if isinstance(references, list):
        for reference in references:
            if isinstance(reference, dict):
                pieces.extend((
                    str(reference.get("title") or ""),
                    str(reference.get("content") or ""),
                ))
    return "\n".join(pieces)


def _supported_cves(record: Dict[str, Any], is_digest: bool) -> str:
    heading_cves = {
        cve.upper()
        for cve in _CVE_PATTERN.findall(str(record.get("advisory_heading") or ""))
    }
    if is_digest:
        supported = heading_cves
    else:
        supported = {
            cve.upper() for cve in _CVE_PATTERN.findall(_source_evidence(record))
        } | heading_cves
    candidates = _CVE_PATTERN.findall(_known_text(record.get("cve_details")))
    return ", ".join(cve.upper() for cve in candidates if cve.upper() in supported)


def _structured_detail(value: Any, max_length: int = 120) -> str:
    text = _known_text(value)
    if (
        len(text) > max_length
        or "\n" in text
        or ";" in text
        or len(text.split()) > 14
    ):
        return ""
    return text


def _product_detail(record: Dict[str, Any]) -> str:
    product = (
        _structured_detail(record.get("affected_products"))
        or _structured_detail(record.get("matched_app_name"))
    )
    evidence = _source_evidence(record).casefold()
    return product if product and product.casefold() in evidence else ""


def _add_hyperlink(paragraph, label: str, url: str) -> None:
    relation_id = paragraph.part.relate_to(
        url,
        RELATIONSHIP_TYPE.HYPERLINK,
        is_external=True,
    )
    hyperlink = OxmlElement("w:hyperlink")
    hyperlink.set(qn("r:id"), relation_id)
    run = OxmlElement("w:r")
    properties = OxmlElement("w:rPr")
    color = OxmlElement("w:color")
    color.set(qn("w:val"), "0563C1")
    underline = OxmlElement("w:u")
    underline.set(qn("w:val"), "single")
    properties.append(color)
    properties.append(underline)
    run.append(properties)
    text = OxmlElement("w:t")
    text.text = label
    run.append(text)
    hyperlink.append(run)
    paragraph._p.append(hyperlink)


class DetailedAdvisoryReportGenerator:
    """Creates source-grounded Word reports using the provided report format."""

    def __init__(self, template_path: Path, ai_evaluator=None):
        self.template_path = Path(template_path)
        self.ai_evaluator = ai_evaluator
        if not self.template_path.is_file():
            raise FileNotFoundError(
                f"Detailed advisory report template not found: {self.template_path}"
            )

    def generate(self, record: Dict[str, Any], output_directory: Path) -> Path:
        heading = _known_text(record.get("advisory_heading"))
        if not heading:
            raise ValueError("Cannot create a detailed report without an advisory heading.")
        output_directory = Path(output_directory)
        output_directory.mkdir(parents=True, exist_ok=True)

        stable_id = _known_text(record.get("advisory_id") or record.get("id"))
        if not stable_id:
            identity = f"{heading}|{_known_text(record.get('link'))}"
            stable_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
        filename = (
            f"{_safe_filename(heading)}_{_safe_filename(stable_id[-12:])}.docx"
        )
        output_path = output_directory / filename
        content = _fallback_report_content(record)
        if self.ai_evaluator is not None:
            generated = self.ai_evaluator.generate_detailed_advisory_report(record)
            if generated:
                content = _merge_generated_content(content, generated)
            else:
                logging.getLogger(__name__).warning(
                    "AI report content was unavailable for advisory %s; "
                    "using source-derived content.",
                    stable_id,
                )

        document = Document(str(self.template_path))
        prototypes = self._capture_template(document)
        self._clear_template_content(document)
        self._set_header_and_footer(document, record)
        self._populate(document, prototypes, record, heading, content)
        document.core_properties.title = heading
        document.core_properties.subject = "Detailed threat intelligence advisory"
        document.save(output_path)
        return output_path.resolve()

    @staticmethod
    def _capture_template(document) -> Dict[str, Any]:
        paragraphs = list(document.paragraphs)
        headings = {
            paragraph.text.strip(): deepcopy(paragraph._p)
            for paragraph in paragraphs
            if paragraph.style.name in {"Heading 1", "Heading 2"}
        }
        title = next(
            paragraph._p for paragraph in paragraphs
            if paragraph.style.name == "Title"
        )
        normal = next(
            paragraph._p for paragraph in paragraphs
            if paragraph.style.name == "Normal" and paragraph.text.strip()
        )
        listing = next(
            paragraph._p for paragraph in paragraphs
            if paragraph.style.name == "List Paragraph"
        )
        code = next(
            paragraph._p for paragraph in paragraphs
            if paragraph.text.strip().startswith('import "hash"')
        )
        if len(document.tables) < 7:
            raise ValueError("The detailed advisory template is missing expected tables.")
        return {
            "title": deepcopy(title),
            "normal": deepcopy(normal),
            "list": deepcopy(listing),
            "code": deepcopy(code),
            "heading1": deepcopy(next(
                paragraph._p for paragraph in paragraphs
                if paragraph.style.name == "Heading 1"
            )),
            "heading2": deepcopy(next(
                paragraph._p for paragraph in paragraphs
                if paragraph.style.name == "Heading 2"
            )),
            "headings": headings,
            "tables": [deepcopy(table._tbl) for table in document.tables[:7]],
        }

    @staticmethod
    def _clear_template_content(document) -> None:
        body = document._element.body
        for child in list(body):
            if child.tag != qn("w:sectPr"):
                body.remove(child)

    @staticmethod
    def _set_header_and_footer(document, record: Dict[str, Any]) -> None:
        classification = _known_text(
            record.get("tlp") or record.get("classification")
        )
        header_text = "THREAT ADVISORY"
        if classification:
            header_text = f"{header_text}  |  {classification}"
        for section in document.sections:
            header = section.header.paragraphs[0]
            DetailedAdvisoryReportGenerator._set_paragraph_text(
                header,
                header_text,
            )

            footer = section.footer.paragraphs[0]
            footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
            DetailedAdvisoryReportGenerator._set_paragraph_text(footer, "Page ")
            run = footer.add_run()
            begin = OxmlElement("w:fldChar")
            begin.set(qn("w:fldCharType"), "begin")
            instruction = OxmlElement("w:instrText")
            instruction.set(qn("xml:space"), "preserve")
            instruction.text = " PAGE "
            separate = OxmlElement("w:fldChar")
            separate.set(qn("w:fldCharType"), "separate")
            placeholder = OxmlElement("w:t")
            placeholder.text = "1"
            end = OxmlElement("w:fldChar")
            end.set(qn("w:fldCharType"), "end")
            run._r.extend((begin, instruction, separate, placeholder, end))

    @staticmethod
    def _set_paragraph_text(paragraph, text: str) -> None:
        run_properties = None
        for child in paragraph._p:
            if child.tag == qn("w:r") and child.rPr is not None:
                run_properties = deepcopy(child.rPr)
                break
        for child in list(paragraph._p):
            if child.tag != qn("w:pPr"):
                paragraph._p.remove(child)
        if text:
            run = paragraph.add_run(str(text))
            if run_properties is not None:
                run._r.insert(0, run_properties)

    @staticmethod
    def _insert_body_element(document, element) -> None:
        body = document._element.body
        if len(body) and body[-1].tag == qn("w:sectPr"):
            body.insert(len(body) - 1, element)
        else:
            body.append(element)

    def _append_paragraph(
        self,
        document,
        prototype,
        text: str = "",
        hyperlink: str = "",
    ):
        element = deepcopy(prototype)
        paragraph = Paragraph(element, document._body)
        self._set_paragraph_text(paragraph, text)
        self._insert_body_element(document, element)
        if hyperlink:
            _add_hyperlink(paragraph, hyperlink, hyperlink)
        return paragraph

    def _append_heading(self, document, prototypes, text: str) -> None:
        prototype = prototypes["headings"].get(text)
        if prototype is None:
            prototype = (
                prototypes["heading1"]
                if re.match(r"^\d+\.", text)
                else prototypes["heading2"]
            )
        self._append_paragraph(document, prototype, text)

    @staticmethod
    def _set_cell_text(cell, text: str) -> None:
        paragraphs = list(cell.paragraphs)
        if not paragraphs:
            paragraph = cell.add_paragraph()
            DetailedAdvisoryReportGenerator._set_paragraph_text(paragraph, text)
            return
        DetailedAdvisoryReportGenerator._set_paragraph_text(paragraphs[0], text)
        for paragraph in paragraphs[1:]:
            cell._tc.remove(paragraph._p)

    def _append_table(
        self,
        document,
        prototype,
        rows: List[List[str]],
        headers: List[str],
    ):
        table_xml = deepcopy(prototype)
        table = Table(table_xml, document._body)
        row_prototype = deepcopy(table.rows[1]._tr) if len(table.rows) > 1 else None
        for row in list(table.rows)[1:]:
            table._tbl.remove(row._tr)
        for index, value in enumerate(headers):
            self._set_cell_text(table.rows[0].cells[index], value)
        if row_prototype is None:
            raise ValueError("The detailed advisory template table has no data-row style.")
        for values in rows:
            table._tbl.append(deepcopy(row_prototype))
            cells = table.rows[-1].cells
            for index, value in enumerate(values):
                self._set_cell_text(cells[index], value)
        self._insert_body_element(document, table_xml)
        return table

    def _append_metadata_table(
        self,
        document,
        prototype,
        rows: List[Tuple[str, str]],
    ) -> None:
        table_xml = deepcopy(prototype)
        table = Table(table_xml, document._body)
        if len(table.rows) != len(rows):
            raise ValueError("The metadata table in the report template has changed.")
        for row, values in zip(table.rows, rows):
            for cell, value in zip(row.cells, values):
                self._set_cell_text(cell, value)
        self._insert_body_element(document, table_xml)

    def _append_scope_table(
        self,
        document,
        prototype,
        content: Dict[str, Any],
    ) -> None:
        table_xml = deepcopy(prototype)
        table = Table(table_xml, document._body)
        cell = table.rows[0].cells[0]
        paragraphs = list(cell.paragraphs)
        if not paragraphs:
            raise ValueError("The advisory scope cell is missing its paragraph style.")
        lines = [
            "ADVISORY SCOPE AND REQUIRED TEAM REVIEW",
            "What this advisory contains:",
            f"Applies to: {content['products'] or 'Not identified in supplied sources'}",
            f"Affected versions: {content['versions'] or 'Not specified in supplied sources'}",
            f"CVE(s): {content['cves'] or 'None stated in supplied sources'}",
            content["scope_note"],
        ]
        prototype_paragraph = deepcopy(
            paragraphs[min(2, len(paragraphs) - 1)]._p
        )
        while len(paragraphs) < len(lines):
            paragraph_xml = deepcopy(prototype_paragraph)
            cell._tc.append(paragraph_xml)
            paragraphs.append(Paragraph(paragraph_xml, cell))
        for paragraph, text in zip(paragraphs, lines):
            self._set_paragraph_text(paragraph, text)
        for paragraph in paragraphs[len(lines):]:
            cell._tc.remove(paragraph._p)
        self._insert_body_element(document, table_xml)

    def _populate(
        self,
        document,
        prototypes: Dict[str, Any],
        record: Dict[str, Any],
        heading: str,
        content: Dict[str, Any],
    ) -> None:
        sources = _source_records(record)
        self._append_paragraph(
            document,
            prototypes["title"],
            f"Threat Intel Advisory: {heading}",
        )
        actors = content["threat_actors"]
        actor_text = (
            "Threat actors: " + "; ".join(actors)
            if actors else "Threat actors: Not identified in supplied sources."
        )
        self._append_paragraph(document, prototypes["normal"], actor_text)

        date_text = _report_date(record)
        self._append_metadata_table(
            document,
            prototypes["tables"][0],
            [
                ("Date", date_text),
                ("Classification", _known_text(
                    record.get("tlp") or record.get("classification")
                ) or "Not specified"),
                ("Severity", content["severity"]),
                ("Confidence", content["confidence"]),
                ("Sources", "; ".join(source["name"] for source in sources)),
                ("Prepared by", "CTI Advisory Automation"),
            ],
        )
        self._append_scope_table(
            document,
            prototypes["tables"][1],
            content,
        )

        self._append_heading(document, prototypes, "1. Summary")
        for point in content["summary_points"]:
            self._append_paragraph(document, prototypes["list"], point)
        self._append_heading(document, prototypes, "2. Why this matters to us")
        self._append_paragraph(document, prototypes["normal"], content["why_it_matters"])

        self._append_heading(document, prototypes, "3. Indicators of Compromise")
        self._append_table(
            document,
            prototypes["tables"][2],
            [[item["type"], item["value"], item["note"]] for item in content["iocs"]],
            ["Type", "Value", "Note"],
        )
        self._append_paragraph(
            document,
            prototypes["normal"],
            content["ioc_limitations"],
        )

        self._append_heading(document, prototypes, "4. Tactics, Techniques and Procedures")
        self._append_table(
            document,
            prototypes["tables"][3],
            [[item["tactic"], item["technique"], item["detail"]]
             for item in content["ttps"]],
            ["Tactic", "Technique", "Detail"],
        )
        self._append_paragraph(
            document,
            prototypes["normal"],
            content["attack_mapping_note"],
        )

        self._append_heading(document, prototypes, "5. Threat Hunt Direction")
        self._append_heading(
            document,
            prototypes,
            "A. Enterprise and asset exposure",
        )
        for item in content["hunt_enterprise"]:
            self._append_paragraph(document, prototypes["list"], item)
        self._append_heading(
            document,
            prototypes,
            "B. Product-specific and technical checks",
        )
        for item in content["hunt_technical"]:
            self._append_paragraph(document, prototypes["list"], item)

        self._append_heading(document, prototypes, "6. Detection Content")
        self._append_heading(document, prototypes, "YARA")
        self._append_paragraph(
            document,
            prototypes["normal"],
            content["detection_summary"],
        )
        self._append_paragraph(
            document,
            prototypes["normal"],
            content["yara_content"],
        )
        self._append_heading(document, prototypes, "Sigma")
        self._append_paragraph(
            document,
            prototypes["normal"],
            content["sigma_content"],
        )

        self._append_heading(
            document,
            prototypes,
            "7. Compensating Control Check Required",
        )
        self._append_paragraph(
            document,
            prototypes["normal"],
            content["controls_intro"],
        )
        self._append_heading(document, prototypes, "A. Security tooling check")
        self._append_paragraph(
            document,
            prototypes["normal"],
            content["tooling_notes"],
        )
        self._append_table(
            document,
            prototypes["tables"][4],
            [[
                item["technology"],
                item["tool"],
                item["signature_status"],
                item["remarks"],
                item["applicable"],
            ] for item in content["tooling_checks"]],
            [
                "Technology",
                "Tool",
                "Signature Status",
                "Remarks",
                "Applicable",
            ],
        )
        self._append_heading(
            document,
            prototypes,
            "B. Compensating control checks",
        )
        self._append_table(
            document,
            prototypes["tables"][5],
            [[
                str(index),
                item["control"],
                item["verify"],
                "Owner to assess",
            ] for index, item in enumerate(content["compensating_controls"], 1)],
            ["#", "Control", "What to verify", "Status"],
        )
        self._append_heading(document, prototypes, "SecOps instructions")
        self._append_paragraph(
            document,
            prototypes["normal"],
            "Suggested actions; owners should confirm applicability before execution.",
        )
        self._append_table(
            document,
            prototypes["tables"][6],
            [[
                str(index),
                item["control"],
                item["instruction"],
            ] for index, item in enumerate(content["secops_instructions"], 1)],
            ["#", "Control", "Instruction for SecOps"],
        )
        if content["incident_response"]:
            self._append_paragraph(
                document,
                prototypes["normal"],
                "If the issue is suspected in your environment:",
            )
            for item in content["incident_response"]:
                self._append_paragraph(document, prototypes["list"], item)

        self._append_heading(document, prototypes, "8. Recommended Actions")
        self._append_heading(document, prototypes, "Immediate (24 to 72 hours)")
        for item in content["immediate_actions"]:
            self._append_paragraph(document, prototypes["list"], item)
        self._append_heading(document, prototypes, "Short term")
        for item in content["short_term_actions"]:
            self._append_paragraph(document, prototypes["list"], item)

        self._append_heading(document, prototypes, "9. References")
        self._append_references(document, prototypes["list"], sources)

    @staticmethod
    def _append_references(document, prototype, sources: List[Dict[str, str]]) -> None:
        for source in sources:
            prefix = source["name"]
            if source["published"]:
                prefix += f" ({source['published']})"
            if source["title"]:
                prefix += f": {source['title']}"
            prefix += ", "
            paragraph = Paragraph(deepcopy(prototype), document._body)
            DetailedAdvisoryReportGenerator._set_paragraph_text(
                paragraph,
                prefix,
            )
            DetailedAdvisoryReportGenerator._insert_body_element(
                document,
                paragraph._p,
            )
            if source["link"].startswith(("http://", "https://")):
                _add_hyperlink(paragraph, source["link"], source["link"])
            elif source["link"]:
                paragraph.add_run(source["link"])


def _report_date(record: Dict[str, Any]) -> str:
    timestamp = record.get("published_timestamp")
    if isinstance(timestamp, (int, float)) and timestamp > 0:
        return datetime.fromtimestamp(timestamp).strftime("%d %B %Y")
    sources = _source_records(record)
    if sources and sources[0]["published"]:
        return sources[0]["published"][:10]
    return datetime.now().strftime("%d %B %Y")


def _source_texts(record: Dict[str, Any]) -> List[str]:
    references = record.get("source_references")
    texts = []
    seen = set()
    if isinstance(references, list):
        for reference in references:
            if not isinstance(reference, dict):
                continue
            content = _known_text(reference.get("content"))
            key = content[:250]
            if content and key not in seen:
                seen.add(key)
                texts.append(content)
    if not texts and _known_text(record.get("source_content")):
        texts.append(_known_text(record.get("source_content")))
    return texts


def _summary_points(record: Dict[str, Any], is_digest: bool) -> List[str]:
    heading = _known_text(record.get("advisory_heading"))
    sources = _source_texts(record)
    cves = _supported_cves(record, is_digest)
    if is_digest:
        cve_text = f" ({cves})" if cves else ""
        return [
            f"The captured newsletter headline identifies {heading}{cve_text}. "
            "The supplied capture does not include article-specific technical "
            "details, affected versions, exploitation status, or remediation."
        ]

    source_sentences = []
    for source in sources:
        source_sentences.extend(re.split(r"(?<=[.!?])\s+", source))
    excerpts = [
        sentence.strip()
        for sentence in source_sentences
        if 25 < len(sentence.strip()) <= 600
        and re.search(r"[.!?][\"')\]]?$", sentence.strip())
    ]
    if excerpts:
        return [f"Source-reported: {sentence}" for sentence in excerpts[:5]]
    return [
        f"The supplied source reports: {heading}.",
        "No article-specific technical details were available in the captured "
        "source text.",
    ]


def _fallback_report_content(record: Dict[str, Any]) -> Dict[str, Any]:
    heading = _known_text(record.get("advisory_heading"))
    is_digest = _is_newsletter_digest(record)
    evidence = "\n".join(_source_texts(record))
    product = _product_detail(record) or "the product named in the advisory"
    cves = _supported_cves(record, is_digest)
    versions = ""
    version_field = _structured_detail(record.get("affected_versions"))
    if version_field and version_field.casefold() in evidence.casefold():
        versions = version_field
    fixed_match = re.search(
        r"\b(?:fixed|patched|released)\s+(?:in\s+)?(?:version\s+)?"
        r"([0-9]+(?:\.[0-9A-Za-z~+-]+){1,4})",
        evidence,
        re.I,
    )
    if not versions and fixed_match and not is_digest:
        versions = f"Fixed release stated by source: {fixed_match.group(1)}"

    if is_digest:
        limitations = (
            "The source is a newsletter capture. It contains the event headline "
            "but not the linked article's technical detail; severity, affected "
            "versions, exploitation status, and repair instructions are not "
            "established here."
        )
    elif not versions:
        limitations = (
            "The supplied source material does not establish a complete affected "
            "version range. Check vendor or distribution advisories for backports."
        )
    else:
        limitations = (
            "The report uses only the supplied source material; verify package "
            "and bundled-component status with the relevant vendor."
        )

    if is_digest:
        why_it_matters = (
            "The captured headline identifies a reported issue, but the available "
            "capture omits technical impact and affected configurations. Determine "
            "applicability from the linked full advisory before acting."
        )
    else:
        why_it_matters = (
            f"The supplied source associates {product} with the reported issue. "
            "Confirm the affected configuration and impact from the linked "
            "advisory before making operational decisions."
        )

    iocs = []
    for raw in re.split(r"[;\r\n]+", str(record.get("iocs") or "")):
        label, separator, value = raw.strip().partition(":")
        value = value.strip()
        if (
            separator
            and label.strip().casefold() in _IOC_LABELS
            and value
            and value.casefold() in evidence.casefold()
        ):
            iocs.append({"type": label.strip(), "value": value, "note": ""})
    if iocs:
        ioc_limitations = (
            "Only explicitly labeled indicators are listed. Validate each "
            "indicator against the original source before blocking."
        )
    else:
        ioc_limitations = (
            "No discrete, validated network or file indicators were identified "
            "in the supplied source material. Reference URLs and CVE links are "
            "not treated as IOCs."
        )

    if re.search(r"use.after.free|sandbox|crafted file", evidence, re.I):
        ttps = [{
            "tactic": "Not stated",
            "technique": "No ATT&CK technique is asserted from the available text.",
            "detail": "Validate exploit behavior against the full source advisory.",
        }]
        hunt_technical = [
            "If the affected workflow processes untrusted files, review its logs "
            "for unexpected child processes; this is a hunt hypothesis, not a "
            "source-confirmed indicator.",
            "Check application, container, and bundled-library versions separately "
            "from the host operating-system package.",
        ]
    else:
        ttps = [{
            "tactic": "Not stated",
            "technique": "Exploit technique not described in supplied source material.",
            "detail": "Do not infer an ATT&CK technique from the headline alone.",
        }]
        hunt_technical = [
            "Obtain the full vendor advisory and identify affected versions before "
            "building a technical hunt or detection.",
            f"Check organization-managed deployments of {product} after the "
            "affected-version range is confirmed.",
        ]

    if is_digest:
        immediate_actions = [
            "Retrieve and review the full advisory for the issue named in the "
            "captured headline.",
            "Confirm affected products, configurations, and remediation from the "
            "vendor before assigning operational priority.",
        ]
        short_term_actions = [
            "Record the vendor-confirmed affected versions and remediation once "
            "the full advisory is available.",
            "Update this report when source-backed technical details are obtained.",
        ]
    else:
        immediate_actions = [
            f"Identify organization-managed systems using {product} and capture "
            "their installed or bundled versions.",
            "Confirm affected and fixed versions with the linked vendor advisory "
            "before prioritizing remediation.",
        ]
        short_term_actions = [
            "Apply the vendor-supported fix where the installed version is affected.",
            "Record unpatched exceptions, system owners, and compensating controls "
            "for follow-up.",
        ]

    controls = [
        {
            "control": "Affected software inventory",
            "verify": (
                f"Locate {product} in endpoints, servers, containers, and "
                "application-bundled components; record the actual runtime version."
            ),
        },
        {
            "control": "Vendor remediation",
            "verify": (
                "Confirm the affected/fixed version range from the vendor or "
                "distribution advisory and verify the applied update."
            ),
        },
        {
            "control": "Exposure reduction",
            "verify": (
                "Where applicable, restrict untrusted input to the affected "
                "processing path until patch status is confirmed."
            ),
        },
    ]
    tooling = [{
        "technology": "Application and endpoint inventory",
        "tool": product,
        "signature_status": "Not assessed",
        "remarks": (
            "No local security-tool or signature-coverage inventory was supplied."
        ),
        "applicable": "Owner to verify",
    }]
    instructions = [
        {
            "control": "Scope",
            "instruction": (
                f"Identify owners and deployed copies of {product}, including "
                "containers and application bundles."
            ),
        },
        {
            "control": "Remediate",
            "instruction": (
                "Compare versions with vendor guidance, apply the supported fix, "
                "and record any systems that cannot be updated."
            ),
        },
        {
            "control": "Validate",
            "instruction": (
                "Confirm the running component version and review the source "
                "limitations before closing the advisory."
            ),
        },
    ]
    return {
        "threat_actors": [],
        "summary_points": _summary_points(record, is_digest),
        "why_it_matters": why_it_matters,
        "scope_note": (
            "This assessment separates source-confirmed details from suggested "
            "team checks. " + limitations
        ),
        "products": (
            product
            if _product_detail(record)
            else "Not identified in supplied sources"
        ),
        "versions": versions,
        "cves": cves,
        "severity": (
            _structured_detail(record.get("severity"))
            if (
                not is_digest
                and _structured_detail(record.get("severity"))
                and _structured_detail(record.get("severity")).casefold()
                in evidence.casefold()
            )
            else "Not stated in supplied sources"
        ),
        "confidence": (
            "Automation-generated from the linked source material; independent "
            "validation is required."
        ),
        "ioc_limitations": ioc_limitations,
        "iocs": iocs or [{
            "type": "Source note",
            "value": "No validated IOCs identified",
            "note": "The reviewed source material does not publish discrete indicators.",
        }],
        "ttps": ttps,
        "attack_mapping_note": (
            "No ATT&CK technique IDs are asserted unless explicitly supported by "
            "the supplied source material."
        ),
        "hunt_enterprise": [
            f"Inventory organization-managed systems that use {product} and "
            "confirm the version with the application owner.",
            "Prioritize internet-facing or user-supplied-content workflows only "
            "where the source confirms those workflows are relevant.",
        ],
        "hunt_technical": hunt_technical,
        "detection_summary": (
            "The supplied sources do not provide a validated YARA/Sigma signature. "
            "The following checks are analyst-generated hunt hypotheses, not "
            "production detections."
        ),
        "yara_content": (
            "No source-provided file sample or validated file signature was "
            "available to support a YARA rule."
        ),
        "sigma_content": (
            "Suggested hunt hypothesis (validate against local logging before "
            "deployment): review the affected component's processing activity "
            "for the source-described behavior and correlate it with the "
            "version and remediation checks above."
        ),
        "tooling_notes": (
            "The report does not contain the organization's security-tool "
            "inventory. Coverage and signature status must be confirmed by "
            "the tool owners."
        ),
        "tooling_checks": tooling,
        "controls_intro": (
            "The controls below are suggested verification steps, not an "
            "assessment of controls already deployed in the environment."
        ),
        "compensating_controls": controls,
        "secops_instructions": instructions,
        "incident_response": [
            "Preserve relevant application and host logs and record the affected "
            "product/version before remediation.",
            "Escalate suspected exploitation through the organization's incident "
            "response process; do not treat an unvalidated hunt hypothesis as "
            "proof of compromise.",
        ],
        "immediate_actions": immediate_actions,
        "short_term_actions": short_term_actions,
        "source_limitations": limitations,
    }


def _merge_generated_content(
    fallback: Dict[str, Any],
    generated: Dict[str, Any],
) -> Dict[str, Any]:
    merged = dict(fallback)
    for field, value in generated.items():
        if isinstance(value, str) and value.strip():
            merged[field] = value.strip()
        elif isinstance(value, list) and value:
            merged[field] = value
    return merged
