import json
import sys

THRESHOLD_PROB = 0.70
SEVERE_LEVELS = ["HIGH", "CRITICAL"]

def has_severe_heuristics(heuristics):
    """True si alguna heurística es HIGH o CRITICAL."""
    return any(h["severity"] in SEVERE_LEVELS for h in heuristics)


def main():

    try:
        with open("analysis_report.json", "r", encoding="utf-8") as f:
            report = json.load(f)
    except FileNotFoundError:
        print("❌ No se encontró analysis_report.json. Ejecuta analyze_repo.py primero.")
        sys.exit(1)

    ml_risky_files = []
    heur_risky_files = []

    for file_path, data in report.items():
        ml_prob = data.get("ml_probability", 0)
        heuristics = data.get("heuristics", [])

        # Riesgo ML >= 70%
        if ml_prob >= THRESHOLD_PROB:
            ml_risky_files.append((file_path, ml_prob))

        # Vulnerabilidades severas
        if has_severe_heuristics(heuristics):
            heur_risky_files.append((file_path, heuristics))

    print("\n===== RESUMEN DE ANÁLISIS (desde analysis_report.json) =====")

    if ml_risky_files:
        print("\n🚨 Archivos con probabilidad ML ≥ 70%:")
        for f, p in ml_risky_files:
            print(f"  - {f}: {p:.2f}")

    if heur_risky_files:
        print("\n❌ Archivos con vulnerabilidades HIGH/CRITICAL:")
        for f, vulns in heur_risky_files:
            names = [v['name'] for v in vulns if v['severity'] in SEVERE_LEVELS]
            print(f"  - {f}: {names}")

    # Condición de fallo del pipeline
    if ml_risky_files or heur_risky_files:
        print("\n🚨 Pipeline fallado por riesgos encontrados.")
        sys.exit(1)

    print("\n✅ No se detectaron riesgos severos.")
    sys.exit(0)


if __name__ == "__main__":
    main()
