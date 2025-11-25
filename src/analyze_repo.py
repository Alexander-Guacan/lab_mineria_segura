import os
import json
import joblib
from pathlib import Path
from predict_risk import extract_features

MODEL_PATH = "data/meta/best_model.pkl"

EXCLUDED_DIRS = {".venv", "__pycache__", ".git", ".github"}

def analyze_repository(base_path="src"):
    model = joblib.load(MODEL_PATH)
    results = []

    for root, dirs, files in os.walk(base_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

        for f in files:
            if f.endswith(".py"):
                file_path = os.path.join(root, f)
                features = extract_features(file_path)

                if features:
                    X = [list(features.values())]
                    pred = model.predict(X)[0]
                    results.append({
                        "file": file_path,
                        "risk": int(pred),
                        "risk_label": "ALTO" if pred == 1 else "BAJO",
                        "features": features
                    })

    return results


if __name__ == "__main__":
    results = analyze_repository("src")
    output = "analysis_report.json"
    Path(output).write_text(
        json.dumps(results, indent=4),
        encoding="utf-8"
    )
    print(f"Reporte generado: {output}")
