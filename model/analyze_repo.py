import os
import sys
from predict_risk import predict_risk
from heuristics import run_heuristics
import json
import glob

def analyze_repository(path):
    files = glob.glob(f"{path}/**/*.py", recursive=True)
    results = {}

    for f in files:
        with open(f, "r", encoding="utf-8") as src:
            code = src.read()

        heur = run_heuristics(code)
        prob = predict_risk(f)

        results[f] = {
            "ml_probability": prob,
            "heuristics": heur
        }

    with open("analysis_report.json", "w", encoding="utf-8") as out:
        json.dump(results, out, indent=4, ensure_ascii=False)

    return results


if __name__ == "__main__":
    folder = sys.argv[1] if len(sys.argv) > 1 else "src"
    analyze_repository(folder)
