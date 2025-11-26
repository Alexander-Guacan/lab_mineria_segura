import json
import sys
from pathlib import Path

REPORT_PATH = "analysis_report.json"

def main():
    if not Path(REPORT_PATH).exists():
        print("ERROR: analysis_report.json no existe. ¿Falló analyze_repo.py?")
        sys.exit(1)

    with open(REPORT_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    high_risk_files = []
    heuristic_findings = []

    for entry in data:
        if entry.get("risk_ml") == 1:
            high_risk_files.append(entry["file"])

        if entry.get("heuristics_detected", 0) > 0:
            heuristic_findings.append({
                "file": entry["file"],
                "issues": entry["heuristics"]
            })

    # Mostrar resultados
    if high_risk_files:
        print("❌ Archivos con riesgo ALTO por modelo ML:")
        for f in high_risk_files:
            print(f"   - {f}")

    if heuristic_findings:
        print("\n❌ Vulnerabilidades detectadas por heurísticas:")
        for item in heuristic_findings:
            print(f"   - {item['file']}: {item['issues']}")

    # Decidir si fallar pipeline
    if high_risk_files or heuristic_findings:
        print("\n🚨 Pipeline fallado por riesgos encontrados.")
        sys.exit(1)

    print("✔ No se encontraron riesgos altos. Pipeline OK.")
    sys.exit(0)


if __name__ == "__main__":
    main()
