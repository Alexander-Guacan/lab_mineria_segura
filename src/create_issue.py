import json
import os

THRESHOLD = 0.70
REPORT_PATH = "analysis_report.json"

def format_percentage(prob):
    """Convierte 0.8234 a 82.34%"""
    return f"{prob * 100:.2f}%"

def generate_issue_body(report):
    high_risk = []
    heuristic_issues = []

    for entry in report:
        file = entry["file"]
        proba = entry.get("risk_probability", 0)
        heuristics = entry.get("heuristics", [])

        if proba >= THRESHOLD:
            high_risk.append((file, proba))

        if heuristics:
            heuristic_issues.append((file, heuristics))

    lines = []

    lines.append("# 🚨 Alerta de Seguridad — Análisis Automático\n")
    lines.append("Se han detectado posibles riesgos en el código analizado.\n")
    lines.append("---\n")

    if high_risk:
        lines.append("## 🔥 Archivos con riesgo ALTO (probabilidad ≥ 70%)\n")
        for file, prob in high_risk:
            lines.append(f"- `{file}` — **{format_percentage(prob)}** de probabilidad de riesgo")
        lines.append("\n")
    else:
        lines.append("## ✔ No se detectó riesgo alto según el modelo ML.\n")

    if heuristic_issues:
        lines.append("## ⚠ Vulnerabilidades detectadas por heurísticas\n")
        for file, issues in heuristic_issues:
            issue_list = ", ".join(issues)
            lines.append(f"- `{file}` — {issue_list}")
        lines.append("\n")
    else:
        lines.append("## ✔ No se detectaron vulnerabilidades basadas en heurísticas.\n")

    lines.append("---\n")
    lines.append("## 📊 Resumen\n")

    total_files = len(report)
    total_ml = len(high_risk)
    total_heur = len(heuristic_issues)

    lines.append(f"- Archivos analizados: **{total_files}**")
    lines.append(f"- Riesgos ML ≥ 70%: **{total_ml}**")
    lines.append(f"- Archivos con heurísticas detectadas: **{total_heur}**\n")

    lines.append("---\n")
    lines.append("> *Este Issue fue generado automáticamente por el sistema de análisis de seguridad (CI/CD DevSecOps).*")

    return "\n".join(lines)

def main():
    if not os.path.exists(REPORT_PATH):
        print("No se encontró analysis_report.json")
        return

    with open(REPORT_PATH, "r", encoding="utf-8") as f:
        report = json.load(f)

    issue_body = generate_issue_body(report)
    print(issue_body)

if __name__ == "__main__":
    main()
