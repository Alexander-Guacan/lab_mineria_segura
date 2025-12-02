import joblib
import json
import sys
import os

from extract_features import extract_metrics_from_file
from heuristics import run_heuristics

MODEL_PATH = "data/meta/best_model.pkl"
THRESHOLD = 0.70


def predict_risk(file_path):

    if not os.path.isfile(MODEL_PATH):
        raise FileNotFoundError("No se encontró data/meta/best_model.pkl. Ejecuta el entrenamiento nuevamente.")

    model = joblib.load(MODEL_PATH)

    features = extract_metrics_from_file(file_path)
    if features is None:
        raise ValueError(f"No se pudieron extraer características del archivo {file_path}")

    features["size_bytes"] = os.path.getsize(file_path)

    X = [[
        features["loc"],
        features["comments"],
        features["functions"],
        features["classes"],
        features["imports"],
        features["ast_nodes"],
        features["control_structures"],
        features["cyclomatic_complexity"],
        features["maintainability_index"],
        features["size_bytes"]
    ]]

    proba = model.predict_proba(X)[0][1]
    risk_flag = int(proba >= THRESHOLD)

    with open(file_path, "r", encoding="utf-8") as f:
        code = f.read()
    heuristics = run_heuristics(code)

    result = {
        "file": file_path,
        "risk_probability": float(proba),
        "risk_flag": risk_flag,
        "heuristics": heuristics
    }

    return result


if __name__ == "__main__":
    file_path = sys.argv[1]
    result = predict_risk(file_path)

    with open("analysis_single.json", "w") as f:
        json.dump(result, f, indent=4)

    print(json.dumps(result, indent=4))
