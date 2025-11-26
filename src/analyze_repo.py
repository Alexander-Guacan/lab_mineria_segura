import os
import json
import joblib
import sys
from pathlib import Path
from predict_risk import extract_features
from heuristics import run_heuristics

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
                code = Path(file_path).read_text(encoding="utf-8")

                features = extract_features(file_path)
                if not features:
                    continue
                X = [list(features.values())]
                pred = model.predict(X)[0]

                heuristics = run_heuristics(code)

                results.append({
                    "file": file_path,
                    "risk_ml": int(pred),
                    "risk_ml_label": "ALTO" if pred == 1 else "BAJO",
                    "heuristics": heuristics,
                    "heuristics_detected": len(heuristics),
                    "features": features
                })

    return results


if __name__ == "__main__":
    file_path = sys.argv[1]
    results = analyze_repository("src" if len(file_path) <= 0 else file_path)
    output = "analysis_report.json"
    Path(output).write_text(json.dumps(results, indent=4), encoding="utf-8")
    print(f"Reporte generado: {output}")
