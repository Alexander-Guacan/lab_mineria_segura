import os
import json
import sys

from predict_risk import predict_risk


EXCLUDED_DIRS = {".venv", "venv", "__pycache__", "data", ".git"}


def analyze_repository(base_path):
    results = []

    for root, dirs, files in os.walk(base_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                print(f"[+] Analizando {file_path}")

                try:
                    result = predict_risk(file_path)
                    results.append(result)

                except Exception as e:
                    print(f"[ERROR] No se pudo analizar {file_path}: {e}")

    with open("analysis_report.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)

    print("\n=== Análisis completado ===")
    print("Resultados guardados en analysis_report.json")

    return results


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "src"
    analyze_repository(target)
