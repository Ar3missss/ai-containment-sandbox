"""
Management command:
  python manage.py train_sentinel_model --data /path/to/dataset.jsonl

Dataset format (JSONL or CSV):
  - text: input text content
  - label: target class (SAFE, MALICIOUS_CODE, DATA_EXFILTRATION, ...)
"""

import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

SAFE_LABELS = {"SAFE", "BENIGN", "NONE", "NORMAL", "NO_THREAT"}


def normalize_label(label: str) -> str:
    value = str(label or "").strip().upper().replace(" ", "_")
    if not value:
        return ""
    if value in SAFE_LABELS:
        return "SAFE"
    return value


def parse_dataset(path: Path) -> Tuple[List[str], List[str]]:
    texts: List[str] = []
    labels: List[str] = []

    def add_record(record: dict) -> None:
        text = (
            record.get("text")
            or record.get("prompt")
            or record.get("input")
            or record.get("content")
            or ""
        )
        label = (
            record.get("label")
            or record.get("category")
            or record.get("threat_category")
            or ""
        )

        text = str(text).strip()
        label = normalize_label(label)

        if not text or not label:
            return

        texts.append(text)
        labels.append(label)

    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        with path.open("r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as e:
                    raise CommandError(f"Invalid JSON at line {line_num}: {e}") from e
                if not isinstance(record, dict):
                    continue
                add_record(record)
    elif suffix == ".csv":
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                add_record(row)
    else:
        raise CommandError("Unsupported dataset format. Use .jsonl or .csv")

    return texts, labels


class Command(BaseCommand):
    help = "Train supervised Sentinel classifier from labeled text data."

    def add_arguments(self, parser):
        parser.add_argument("--data", required=True, help="Path to training dataset (.jsonl or .csv)")
        parser.add_argument(
            "--output",
            default="",
            help="Output model path (.joblib). Defaults to SENTINEL_CONFIG['ML_MODEL_PATH']",
        )
        parser.add_argument("--test-size", type=float, default=0.2, help="Validation split fraction (0.0-0.5)")
        parser.add_argument("--max-features", type=int, default=120000, help="TF-IDF max feature count")
        parser.add_argument("--min-df", type=int, default=2, help="TF-IDF min document frequency")
        parser.add_argument("--ngram-max", type=int, default=2, help="Max n-gram size")
        parser.add_argument("--max-iter", type=int, default=2500, help="Logistic regression max iterations")
        parser.add_argument(
            "--class-weight",
            choices=["balanced", "none"],
            default="balanced",
            help="Use class balancing for imbalanced datasets",
        )

    def handle(self, *args, **options):
        try:
            import joblib
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.linear_model import LogisticRegression
            from sklearn.metrics import accuracy_score, classification_report
            from sklearn.model_selection import train_test_split
            from sklearn.pipeline import Pipeline
        except Exception as e:
            raise CommandError(
                "Missing training dependencies. Install: pip install scikit-learn joblib"
            ) from e

        dataset_path = Path(options["data"]).expanduser()
        if not dataset_path.exists():
            raise CommandError(f"Dataset file not found: {dataset_path}")

        configured_output = settings.SENTINEL_CONFIG.get(
            "ML_MODEL_PATH",
            settings.BASE_DIR / "sentinel" / "model_store" / "sentinel_classifier.joblib",
        )
        output_raw = options["output"] or configured_output
        output_path = Path(str(output_raw)).expanduser()
        if not output_path.is_absolute():
            output_path = Path(settings.BASE_DIR) / output_path

        texts, labels = parse_dataset(dataset_path)
        if len(texts) < 50:
            raise CommandError(
                f"Dataset too small ({len(texts)} records). Provide at least 50 labeled samples."
            )

        label_counts = Counter(labels)
        if len(label_counts) < 2:
            raise CommandError("Training requires at least 2 distinct labels.")

        self.stdout.write(self.style.SUCCESS(f"Loaded {len(texts)} records from {dataset_path}"))
        self.stdout.write(f"Label distribution: {dict(label_counts)}")

        test_size = max(0.0, min(0.5, float(options["test_size"])))
        use_test_split = test_size > 0 and all(count >= 2 for count in label_counts.values())

        if use_test_split:
            X_train, X_test, y_train, y_test = train_test_split(
                texts,
                labels,
                test_size=test_size,
                random_state=42,
                stratify=labels,
            )
        else:
            X_train, y_train = texts, labels
            X_test, y_test = [], []
            self.stdout.write(
                self.style.WARNING(
                    "Skipping stratified validation split because some classes have fewer than 2 samples."
                )
            )

        class_weight = None if options["class_weight"] == "none" else "balanced"
        ngram_max = max(1, int(options["ngram_max"]))

        pipeline = Pipeline(
            steps=[
                (
                    "tfidf",
                    TfidfVectorizer(
                        lowercase=True,
                        strip_accents="unicode",
                        ngram_range=(1, ngram_max),
                        max_features=max(5000, int(options["max_features"])),
                        min_df=max(1, int(options["min_df"])),
                        sublinear_tf=True,
                    ),
                ),
                (
                    "clf",
                    LogisticRegression(
                        max_iter=max(500, int(options["max_iter"])),
                        class_weight=class_weight,
                        solver="lbfgs",
                    ),
                ),
            ]
        )

        pipeline.fit(X_train, y_train)

        metrics = {
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "train_samples": len(X_train),
            "labels": sorted(label_counts.keys()),
            "label_distribution": dict(label_counts),
            "test_size": test_size if use_test_split else 0.0,
            "accuracy": None,
            "classification_report": None,
        }

        if X_test:
            y_pred = pipeline.predict(X_test)
            acc = float(accuracy_score(y_test, y_pred))
            report = classification_report(y_test, y_pred, digits=3, zero_division=0)
            metrics["accuracy"] = round(acc, 4)
            metrics["classification_report"] = report

            self.stdout.write(self.style.SUCCESS(f"Validation accuracy: {acc:.4f}"))
            self.stdout.write("Classification report:\n" + report)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "labels": sorted(label_counts.keys()),
            "pipeline": pipeline,
            "vectorizer": "tfidf_word_ngrams",
            "model": "logistic_regression",
        }
        joblib.dump(payload, output_path)

        metrics_path = output_path.with_suffix(".metrics.json")
        metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

        self.stdout.write(self.style.SUCCESS(f"Saved model to: {output_path}"))
        self.stdout.write(self.style.SUCCESS(f"Saved metrics to: {metrics_path}"))
