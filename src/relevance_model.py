import math
import re
from collections import Counter
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

from openpyxl.styles import Alignment, Font, PatternFill


class AdvisoryRelevanceModel:
    MIN_LABELS_PER_CLASS = 5
    STOP_WORDS = {
        "about", "after", "against", "also", "and", "are", "because", "been",
        "before", "being", "between", "but", "can", "could", "critical", "during",
        "each", "from", "have", "into", "its", "more", "most", "multiple", "new",
        "not", "our", "over", "patch", "patches", "security", "should", "that",
        "their", "there", "these", "this", "through", "under", "update", "updates",
        "using", "uses", "vulnerability", "vulnerabilities", "was", "were", "which",
        "with", "would",
    }

    def __init__(self):
        self.documents: Dict[str, List[Counter]] = {"Selected": [], "Rejected": []}
        self.vocabulary = set()

    @staticmethod
    def normalize_decision(decision: Any) -> str:
        normalized = str(decision or "").strip().casefold()
        if "previously reported" in normalized:
            return "Previously Reported"
        if "rejected" in normalized or normalized in {"no", "false", "0"}:
            return "Rejected"
        if "selected" in normalized or normalized in {"yes", "true", "1", "☑"}:
            return "Selected"
        return "Pending"

    @classmethod
    def _features(cls, record: Dict[str, Any]) -> Counter:
        features = Counter()
        text = " ".join(
            str(record.get(field) or "")
            for field in ("advisory_heading", "impact_summary", "source_name")
        )
        for token in re.findall(r"[a-z][a-z0-9+#.-]{2,}", text.casefold()):
            token = token.strip(".-")
            if token and token not in cls.STOP_WORDS and token != "cve":
                features[f"term:{token}"] += 1

        for app in re.split(r"[,;/|]", str(record.get("matched_app_name") or "")):
            app_tokens = re.findall(r"[a-z][a-z0-9+#.-]{1,}", app.casefold())
            for token in app_tokens:
                token = token.strip(".-")
                if token and token not in cls.STOP_WORDS:
                    features[f"app:{token}"] += 3

        severity = str(record.get("severity") or "").strip().casefold()
        if severity:
            features[f"severity:{severity}"] = 1
        category = str(record.get("advisory_type") or "").strip().casefold()
        if category:
            features[f"type:{category}"] = 1
        if re.search(r"\bCVE-\d{4}-\d{4,}\b", str(record.get("cve_details") or ""), re.I):
            features["has:cve"] = 1
        return features

    def fit(self, records: Iterable[Dict[str, Any]]) -> Dict[str, int]:
        self.documents = {"Selected": [], "Rejected": []}
        self.vocabulary.clear()
        for record in records:
            label = self.normalize_decision(record.get("review_decision"))
            if label not in self.documents:
                continue
            features = self._features(record)
            self.documents[label].append(features)
            self.vocabulary.update(features)
        return {label: len(items) for label, items in self.documents.items()}

    @property
    def ready(self) -> bool:
        return all(
            len(self.documents[label]) >= self.MIN_LABELS_PER_CLASS
            for label in ("Selected", "Rejected")
        )

    def _predict_features(
        self,
        features: Counter,
        require_ready: bool = True,
    ) -> Optional[float]:
        if require_ready and not self.ready:
            return None
        if any(not self.documents[label] for label in self.documents):
            return None

        vocabulary = self.vocabulary
        vocabulary_size = max(len(vocabulary), 1)
        log_probabilities = {}
        total_documents = sum(len(self.documents[label]) for label in self.documents)
        for label in ("Selected", "Rejected"):
            class_documents = self.documents[label]
            class_counts = Counter()
            for document in class_documents:
                class_counts.update(document)
            total_terms = sum(class_counts.values())
            log_probability = math.log(len(class_documents) / total_documents)
            for feature, count in features.items():
                feature_probability = (
                    class_counts.get(feature, 0) + 1
                ) / (total_terms + vocabulary_size)
                log_probability += count * math.log(feature_probability)
            log_probabilities[label] = log_probability

        difference = log_probabilities["Rejected"] - log_probabilities["Selected"]
        if difference >= 700:
            return 0.0
        if difference <= -700:
            return 1.0
        return 1 / (1 + math.exp(difference))

    def predict(self, record: Dict[str, Any]) -> Optional[float]:
        return self._predict_features(self._features(record))

    def _cross_validated_accuracy(self) -> Optional[Tuple[float, float]]:
        if any(len(self.documents[label]) < 2 for label in self.documents):
            return None

        correct = Counter()
        totals = Counter()
        fold_count = min(
            5,
            min(len(self.documents["Selected"]), len(self.documents["Rejected"])),
        )
        for fold in range(fold_count):
            training = AdvisoryRelevanceModel()
            validation = []
            for label, documents in self.documents.items():
                training.documents[label] = [
                    document for index, document in enumerate(documents)
                    if index % fold_count != fold
                ]
                validation.extend(
                    (label, document)
                    for index, document in enumerate(documents)
                    if index % fold_count == fold
                )
            training.vocabulary = set().union(
                *(
                    set(document)
                    for class_documents in training.documents.values()
                    for document in class_documents
                )
            )
            for label, document in validation:
                score = training._predict_features(document, require_ready=False)
                predicted = "Selected" if score is not None and score >= 0.5 else "Rejected"
                totals[label] += 1
                correct[label] += predicted == label

        accuracy = sum(correct.values()) / sum(totals.values())
        balanced_accuracy = sum(
            correct[label] / totals[label] for label in ("Selected", "Rejected")
        ) / 2
        return accuracy, balanced_accuracy

    def _top_signals(self, selected: bool) -> List[str]:
        positive = self.documents["Selected"]
        negative = self.documents["Rejected"]
        selected_counts = Counter()
        rejected_counts = Counter()
        for document in positive:
            selected_counts.update(document.keys())
        for document in negative:
            rejected_counts.update(document.keys())

        selected_size = max(len(positive), 1)
        rejected_size = max(len(negative), 1)
        candidates = set(selected_counts) | set(rejected_counts)
        ranked = []
        for feature in candidates:
            selected_rate = (selected_counts[feature] + 0.5) / (selected_size + 1)
            rejected_rate = (rejected_counts[feature] + 0.5) / (rejected_size + 1)
            lift = math.log(selected_rate / rejected_rate)
            if not selected:
                lift = -lift
            support = selected_counts[feature] if selected else rejected_counts[feature]
            if lift > 0 and support >= 2:
                ranked.append((lift, feature, support))

        ranked.sort(reverse=True)
        return [
            f"{feature.split(':', 1)[-1]} ({support} reviewed)"
            for _, feature, support in ranked[:10]
        ]

    def tracker_summary(self) -> Dict[str, Any]:
        counts = {label: len(self.documents[label]) for label in self.documents}
        accuracy = self._cross_validated_accuracy()
        return {
            "counts": counts,
            "ready": self.ready,
            "accuracy": accuracy,
            "selected_signals": self._top_signals(selected=True),
            "rejected_signals": self._top_signals(selected=False),
            "selected_needed": max(0, self.MIN_LABELS_PER_CLASS - counts["Selected"]),
            "rejected_needed": max(0, self.MIN_LABELS_PER_CLASS - counts["Rejected"]),
        }

    def update_tracker_sheet(self, workbook) -> Dict[str, Any]:
        summary = self.tracker_summary()
        review_counts = Counter()
        master_total = 0
        eligible_selected = 0
        if "Summary" in workbook.sheetnames:
            summary_ws = workbook["Summary"]
            columns = {
                str(cell.value).strip(): cell.column
                for cell in summary_ws[1]
                if cell.value is not None
            }
            heading_column = columns.get("Advisory Heading")
            decision_column = columns.get("Review Decision")
            severity_column = columns.get("Severity")
            if heading_column:
                for row_idx in range(2, summary_ws.max_row + 1):
                    if not summary_ws.cell(row_idx, heading_column).value:
                        continue
                    master_total += 1
                    decision = self.normalize_decision(
                        summary_ws.cell(row_idx, decision_column).value
                        if decision_column else None
                    )
                    review_counts[decision] += 1
                    severity = str(
                        summary_ws.cell(row_idx, severity_column).value or ""
                        if severity_column else ""
                    ).strip().upper()
                    if decision == "Selected" and severity != "LOW":
                        eligible_selected += 1
        report_headings = set()
        if "Summary" in workbook.sheetnames:
            summary_ws = workbook["Summary"]
            columns = {
                str(cell.value).strip(): cell.column
                for cell in summary_ws[1]
                if cell.value is not None
            }
            heading_column = columns.get("Advisory Heading")
            if heading_column:
                report_headings = {
                    str(summary_ws.cell(row_idx, heading_column).value or "").strip().casefold()
                    for row_idx in range(2, summary_ws.max_row + 1)
                    if summary_ws.cell(row_idx, heading_column).value
                }
        generated_reports = sum(
            worksheet.title.startswith(("Advisory Document ", "Report - "))
            or (
                worksheet.title not in {"Summary", "Learning Tracker"}
                and str(worksheet["A2"].value or "").strip().casefold() in report_headings
            )
            for worksheet in workbook.worksheets
        )
        sheet_name = "Learning Tracker"
        worksheet = workbook[sheet_name] if sheet_name in workbook.sheetnames else workbook.create_sheet(sheet_name)
        worksheet.delete_rows(1, worksheet.max_row)
        worksheet.sheet_view.showGridLines = False
        worksheet.column_dimensions["A"].width = 34
        worksheet.column_dimensions["B"].width = 88
        worksheet.freeze_panes = "A2"

        header_fill = PatternFill(fill_type="solid", fgColor="1B365D")
        for column, value in enumerate(("Learning measure", "Current result"), start=1):
            cell = worksheet.cell(row=1, column=column, value=value)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = header_fill
            cell.alignment = Alignment(vertical="center", wrap_text=True)

        if summary["ready"]:
            accuracy, balanced_accuracy = summary["accuracy"] or (0.0, 0.0)
            status = "Suggestions enabled; manual selection is still required."
            learnings = (
                f"Cross-validated accuracy: {accuracy:.0%}; "
                f"balanced accuracy: {balanced_accuracy:.0%}."
            )
        else:
            status = "Collecting human labels; suggestions are not active."
            learnings = (
                f"Need {summary['selected_needed']} more Selected and "
                f"{summary['rejected_needed']} more Rejected labels before suggestions begin."
            )

        learned_terms = []
        if summary["selected_signals"]:
            learned_terms.append("More often selected: " + ", ".join(summary["selected_signals"]))
        if summary["rejected_signals"]:
            learned_terms.append("More often rejected: " + ", ".join(summary["rejected_signals"]))
        if not learned_terms:
            learned_terms.append("Not enough reviewed examples to identify reliable patterns yet.")

        rows = [
            ("Last updated", datetime.now().strftime("%Y-%m-%d %H:%M")),
            ("Advisories in master list", master_total),
            ("Awaiting human review", review_counts["Pending"]),
            ("Selected by a person", review_counts["Selected"]),
            ("Selected and eligible for reports", eligible_selected),
            ("Rejected by a person", review_counts["Rejected"]),
            ("Previously reported", review_counts["Previously Reported"]),
            ("Detailed report sheets in workbook", generated_reports),
            ("Model status", status),
            ("Reviewed advisories", summary["counts"]["Selected"] + summary["counts"]["Rejected"]),
            ("Selected labels", summary["counts"]["Selected"]),
            ("Rejected labels", summary["counts"]["Rejected"]),
            ("Learning check", learnings),
            ("Patterns learned", "\n".join(learned_terms)),
            ("Learning method", "Weighted Naive Bayes baseline; cross-validation is an estimate, not a production-accuracy guarantee."),
            ("Publishing safeguard", "Detailed reports are generated only after an explicit Selected decision; the model cannot publish."),
            ("Training source", "Human Review Decision values in the Master Summary. Advisory format examples are templates, not relevance labels."),
        ]
        for row_idx, (label, value) in enumerate(rows, start=2):
            worksheet.cell(row=row_idx, column=1, value=label)
            cell = worksheet.cell(row=row_idx, column=2, value=value)
            cell.alignment = Alignment(vertical="top", wrap_text=True)
            worksheet.cell(row=row_idx, column=1).font = Font(bold=True)
            if label in {"Learning check", "Patterns learned"}:
                worksheet.row_dimensions[row_idx].height = 70
        return summary
