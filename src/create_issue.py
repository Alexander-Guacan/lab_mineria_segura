import json
from pathlib import Path

REPORT_FILE = "analysis_report.json"

def build_issue_markdown():
    if not Path(REPORT_FILE).exists():
        return "# Error\nNo se encontró analysis_report.json."

    with open(REPORT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    high_risk_files = []
    heuristic_findings = []

    for entry in data:
        if entry.get("risk_ml") == 1:
            high_risk_files.append(entry["file"])
        
        if entry.get("heuristics_detected", 0) > 0:
            heuristic_findings.append(entry)

    md = "# 🚨 Riesgos de seguridad detectados\n"
    md += "El análisis automático identificó posibles vulnerabilidades.\n\n"

    if high_risk_files:
        md += "## 🔴 Archivos con riesgo ALTO (modelo ML)\n"
        for f in high_risk_files:
            md += f"- `{f}`\n"
        md += "\n"

    if heuristic_findings:
        md += "## 🟠 Vulnerabilidades detectadas (heurísticas)\n"
        for item in heuristic_findings:
            md += f"- `{item['file']}`: {item['heuristics']}\n"
        md += "\n"

    md += "## 🛠 Recomendaciones\n"
    md += "- Revisar los archivos afectados.\n"
    md += "- Mitigar las vulnerabilidades reportadas.\n"
    md += "- Considerar agregar validaciones adicionales.\n"

    return md

if __name__ == "__main__":
    print(build_issue_markdown())
