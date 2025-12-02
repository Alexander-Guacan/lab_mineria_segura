import json
import sys

THRESHOLD = 0.70

def main():
    with open("analysis_report.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    high_risk = []
    heuristic_risk = []

    for entry in data:
        file = entry["file"]
        proba = entry.get("risk_probability", 0)
        heuristics = entry.get("heuristics", [])

        if proba >= THRESHOLD:
            high_risk.append((file, proba))

        if heuristics:
            heuristic_risk.append((file, heuristics))

    print("\n=== RESULTADOS DEL ANÁLISIS DE SEGURIDAD ===\n")

    if high_risk:
        print("❌ Archivos con riesgo ALTO (probabilidad ≥ 70%):")
        for f, p in high_risk:
            print(f"   - {f} (probabilidad: {p:.2f})")

    if heuristic_risk:
        print("\n❌ Vulnerabilidades detectadas por heurísticas:")
        for f, issues in heuristic_risk:
            print(f"   - {f}: {issues}")

    # Falla del pipeline
    if high_risk or heuristic_risk:
        print("\n🚨 Pipeline fallado por riesgos detectados.")
        sys.exit(1)

    print("\n✅ No se detectaron riesgos. Pipeline exitoso.")
    sys.exit(0)


if __name__ == "__main__":
    main()
