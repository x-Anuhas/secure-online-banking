"""Explainable login and transfer risk scoring backed by sklearn classifiers."""

from dataclasses import asdict, dataclass
from math import asin, cos, radians, sin, sqrt

import numpy as np
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier


@dataclass(frozen=True)
class RiskFeatures:
    """Measured signals supplied to the risk engine."""

    distance_km: float = 0.0
    interval_hours: float = 0.0
    physical_speed_kmh: float = 0.0
    new_device: int = 0
    login_velocity: float = 0.0
    amount_ratio: float = 1.0

    def vector(self) -> list[float]:
        return [
            self.distance_km,
            self.interval_hours,
            self.physical_speed_kmh,
            float(self.new_device),
            self.login_velocity,
            self.amount_ratio,
        ]


def train_risk_classifiers(
    features: np.ndarray, labels: np.ndarray
) -> tuple[DecisionTreeClassifier, Pipeline]:
    """Train the classifier pair used by both the app and evaluation CLI."""
    tree = DecisionTreeClassifier(
        max_depth=4, class_weight="balanced", random_state=42
    ).fit(features, labels)
    knn = make_pipeline(
        StandardScaler(),
        KNeighborsClassifier(n_neighbors=3, weights="distance"),
    ).fit(features, labels)
    return tree, knn


def distance_km(
    latitude_a: float | None,
    longitude_a: float | None,
    latitude_b: float | None,
    longitude_b: float | None,
) -> float:
    """Compute great-circle distance using the Haversine formula."""
    if None in (latitude_a, longitude_a, latitude_b, longitude_b):
        return 0.0
    lat_a, lon_a, lat_b, lon_b = map(
        radians, (latitude_a, longitude_a, latitude_b, longitude_b)
    )
    delta_lat = lat_b - lat_a
    delta_lon = lon_b - lon_a
    haversine = (
        sin(delta_lat / 2) ** 2
        + cos(lat_a) * cos(lat_b) * sin(delta_lon / 2) ** 2
    )
    return 6371.0 * 2 * asin(sqrt(min(1.0, haversine)))


class RiskEngine:
    """Combine deterministic guardrails with a decision tree and scaled KNN."""

    def __init__(self) -> None:
        training_data = np.array(
            [
                [0, 8, 0, 0, 1, 1],
                [5, 3, 2, 0, 2, 1],
                [20, 5, 4, 0, 2, 1.5],
                [0, 2, 0, 0, 3, 2],
                [10, 1, 10, 1, 3, 1],
                [250, 2, 125, 1, 4, 2],
                [700, 1, 700, 0, 5, 3],
                [900, 1, 900, 1, 2, 1],
                [1200, 1, 1200, 0, 2, 1],
                [0, 0.1, 0, 1, 15, 1],
                [30, 0.05, 600, 1, 18, 8],
                [0, 0.02, 0, 0, 20, 6],
                [80, 0.5, 160, 1, 10, 1],
                [2, 12, 0.2, 0, 1, 0.5],
                [600, 1, 600, 1, 13, 7],
                [3, 0.3, 10, 0, 4, 6],
                [0, 4, 0, 0, 1, 7],
                [150, 0.1, 1500, 1, 16, 2],
            ],
            dtype=float,
        )
        labels = np.array(
            [0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 1, 0, 2, 2, 2, 2]
        )
        self.tree, self.knn = train_risk_classifiers(training_data, labels)

    def assess(
        self,
        features: RiskFeatures,
        amount_ratio_limit: float = 5.0,
        *,
        block_on_model_consensus: bool = False,
    ) -> dict[str, object]:
        """Return model/policy severity, with optional classifier-consensus blocking."""
        model_features = features.vector()
        if features.amount_ratio <= amount_ratio_limit:
            model_features[-1] = 1.0
        values = np.array([model_features], dtype=float)
        tree_prediction = int(self.tree.predict(values)[0])
        knn_prediction = int(self.knn.predict(values)[0])
        tree_probabilities = self.tree.predict_proba(values)[0]
        knn_probabilities = self.knn.predict_proba(values)[0]
        tree_score = sum(
            float(probability) * float(label) / 2
            for probability, label in zip(tree_probabilities, self.tree.classes_)
        )
        knn_score = sum(
            float(probability) * float(label) / 2
            for probability, label in zip(knn_probabilities, self.knn.classes_)
        )
        model_score = (tree_score + knn_score) / 2

        reasons: list[str] = []
        policy_level = 0
        if features.amount_ratio > amount_ratio_limit:
            policy_level = max(policy_level, 1)
            reasons.append(
                "Transfer exceeds the configured typical amount threshold "
                f"({amount_ratio_limit:g}x)."
            )
        if features.login_velocity > 12:
            policy_level = 2
            reasons.append("Unusually high login velocity.")
        if features.physical_speed_kmh > 900:
            policy_level = 2
            reasons.append("Implausible travel speed between observed logins.")
        elif features.physical_speed_kmh > 500:
            policy_level = max(policy_level, 1)
            reasons.append("High travel speed between observed logins.")
        if features.new_device:
            policy_level = max(policy_level, 1)
            reasons.append("This device has not been seen on the account.")

        policy_score = policy_level / 2
        score = max(model_score, policy_score)
        classifier_high_consensus = tree_prediction == 2 and knn_prediction == 2
        if block_on_model_consensus and classifier_high_consensus:
            score = max(score, 1.0)
        names = ("LOW", "MEDIUM", "HIGH")
        if score > 0.75:
            level = 2
        elif score >= 0.4:
            level = 1
        else:
            level = 0
        actions = ("allow", "require_pin", "block")
        if classifier_high_consensus and policy_level < 2:
            reasons.append("Both trained classifiers identified a high-risk pattern.")
        if not reasons and level:
            reasons.append("The trained anomaly classifier identified an unusual pattern.")
        if level == 0:
            reasons.append("No significant anomaly was detected.")
        return {
            "level": names[level],
            "action": actions[level],
            "score": score,
            "reasons": reasons,
            "features": asdict(features),
            "model_predictions": {
                "decision_tree": names[tree_prediction],
                "knn": names[knn_prediction],
            },
        }
