"""Train and evaluate risk classifiers using synthetic or anonymized CSV data."""

import argparse
import csv
from pathlib import Path

import numpy as np
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

from risk_engine import train_risk_classifiers


FEATURE_COLUMNS = (
    "distance_km",
    "interval_hours",
    "physical_speed_kmh",
    "new_device",
    "login_velocity",
    "amount_ratio",
)
CLASS_NAMES = ("LOW", "MEDIUM", "HIGH")


def synthetic_dataset(
    samples_per_class: int = 600, random_state: int = 42
) -> tuple[np.ndarray, np.ndarray]:
    """Create labeled example signals without using real customer information."""
    if samples_per_class < 10:
        raise ValueError("Generate at least 10 synthetic examples per class.")

    random = np.random.default_rng(random_state)
    labels = np.repeat(np.arange(3), samples_per_class)
    features = np.zeros((len(labels), len(FEATURE_COLUMNS)), dtype=float)

    for index, label in enumerate(labels):
        interval = random.uniform(0.25, 24.0)
        distance = random.uniform(0, 250)
        speed = distance / interval
        new_device = 0.0
        login_velocity = random.uniform(0, 5)
        amount_ratio = random.uniform(0.1, 2.0)

        if label == 1:
            signal = random.integers(0, 4)
            if signal == 0:
                new_device = 1.0
            elif signal == 1:
                speed = random.uniform(520, 880)
                distance = speed * interval
            elif signal == 2:
                login_velocity = random.uniform(6, 12)
            else:
                amount_ratio = random.uniform(2, 4.9)
        elif label == 2:
            signal = random.integers(0, 3)
            if signal == 0:
                amount_ratio = random.uniform(5.1, 12)
            elif signal == 1:
                login_velocity = random.uniform(13, 30)
            else:
                speed = random.uniform(901, 1800)
                distance = speed * interval

        features[index] = (
            distance,
            interval,
            speed,
            new_device,
            login_velocity,
            amount_ratio,
        )

    order = random.permutation(len(labels))
    return features[order], labels[order]


def load_csv_dataset(path: Path) -> tuple[np.ndarray, np.ndarray]:
    """Read numeric, de-identified risk features and labels from CSV."""
    features: list[list[float]] = []
    labels: list[int] = []
    required_columns = set(FEATURE_COLUMNS) | {"label"}

    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames is None or not required_columns.issubset(reader.fieldnames):
            expected = ", ".join((*FEATURE_COLUMNS, "label"))
            raise ValueError(f"CSV must include these columns: {expected}")

        for line_number, row in enumerate(reader, start=2):
            try:
                values = [float(row[column]) for column in FEATURE_COLUMNS]
                label_value = float(row["label"])
            except (TypeError, ValueError) as exc:
                raise ValueError(f"CSV line {line_number} has a non-numeric value.") from exc
            if (
                not np.isfinite(values).all()
                or not np.isfinite(label_value)
                or not label_value.is_integer()
                or int(label_value) not in range(len(CLASS_NAMES))
            ):
                raise ValueError(
                    f"CSV line {line_number} has invalid features or label; "
                    "label must be 0, 1, or 2."
                )
            features.append(values)
            labels.append(int(label_value))

    if not features:
        raise ValueError("CSV contains no labeled examples.")
    return np.asarray(features, dtype=float), np.asarray(labels, dtype=int)


def _report(name: str, expected: np.ndarray, predicted: np.ndarray) -> None:
    matrix = confusion_matrix(expected, predicted, labels=[0, 1, 2])
    precision, recall, f1, _ = precision_recall_fscore_support(
        expected,
        predicted,
        labels=[0, 1, 2],
        average="macro",
        zero_division=0,
    )
    print(f"\n{name}")
    print("Confusion matrix (actual rows, predicted columns; LOW, MEDIUM, HIGH):")
    for row in matrix:
        print("  " + " ".join(f"{int(value):5d}" for value in row))
    print(f"Macro precision: {precision:.3f}")
    print(f"Macro recall:    {recall:.3f}")
    print(f"Macro F1-score:  {f1:.3f}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--csv",
        type=Path,
        help=(
            "Optional anonymized CSV with columns: "
            + ", ".join((*FEATURE_COLUMNS, "label"))
        ),
    )
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    arguments = parser.parse_args()

    if not 0.1 <= arguments.test_size <= 0.4:
        parser.error("--test-size must be between 0.1 and 0.4.")

    try:
        features, labels = (
            load_csv_dataset(arguments.csv)
            if arguments.csv
            else synthetic_dataset(random_state=arguments.seed)
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    counts = np.bincount(labels, minlength=len(CLASS_NAMES))
    if np.any(counts < 10):
        parser.error("Provide at least 10 examples for each label 0, 1, and 2.")

    train_features, test_features, train_labels, test_labels = train_test_split(
        features,
        labels,
        test_size=arguments.test_size,
        random_state=arguments.seed,
        stratify=labels,
    )
    tree, knn = train_risk_classifiers(train_features, train_labels)
    tree_predictions = tree.predict(test_features)
    knn_predictions = knn.predict(test_features)

    dataset_name = "CSV data" if arguments.csv else "synthetic data"
    print(
        f"Dataset: {dataset_name} | rows: {len(labels)} | "
        f"train: {len(train_labels)} | validation: {len(test_labels)}"
    )
    print("Labels: 0=LOW, 1=MEDIUM, 2=HIGH")
    _report("Decision tree", test_labels, tree_predictions)
    _report("Scaled K-nearest neighbors", test_labels, knn_predictions)
    _report("Combined maximum-severity prediction", test_labels,
            np.maximum(tree_predictions, knn_predictions))
    print(
        "\nThese metrics measure synthetic or supplied labeled data only. "
        "They do not certify real-world fraud detection or approve a model for production."
    )


if __name__ == "__main__":
    main()
