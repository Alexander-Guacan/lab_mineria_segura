import os
import joblib
from extract_features import extract_metrics_from_file

MODEL_PATH = "data/meta/best_model.pkl"

FEATURES = [
    "loc",
    "comments",
    "functions",
    "classes",
    "imports",
    "ast_nodes",
    "control_structures",
    "cyclomatic_complexity",
    "maintainability_index",
    "size_bytes"
]


def predict_risk(filepath):
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("No se encontró best_model.pkl. Entrena el modelo primero.")

    model = joblib.load(MODEL_PATH)
    metrics = extract_metrics_from_file(filepath)

    if metrics is None:
        return 0.0

    if "size_bytes" not in metrics:
        metrics["size_bytes"] = os.path.getsize(filepath)

    X = [[metrics[feat] for feat in FEATURES]]

    proba = model.predict_proba(X)[0][1]  # probabilidad clase 1 (riesgo)
    return float(proba)
