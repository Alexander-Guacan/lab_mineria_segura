import json

def main():
    with open("analysis_report.json", "r", encoding="utf-8") as f:
        report = json.load(f)

    issue_lines = []
    issue_lines.append("# 🚨 Reporte Automático de Seguridad\n")

    for file_path, data in report.items():

        ml_prob = data["ml_probability"]
        heuristics = data["heuristics"]

        if ml_prob < 0.70 and not any(h["severity"] in ["HIGH", "CRITICAL"] for h in heuristics):
            continue  # solo reportamos lo grave

        issue_lines.append(f"## 📌 {file_path}")
        issue_lines.append(f"- **Riesgo ML:** {ml_prob:.2f}")

        if heuristics:
            issue_lines.append("- **Heurísticas detectadas:**")
            for h in heuristics:
                if h["severity"] in ["HIGH", "CRITICAL"]:
                    issue_lines.append(
                        f"  - **{h['name']}** ({h['severity']}) → {h['detail']}"
                    )

        issue_lines.append("")

    print("\n".join(issue_lines))


if __name__ == "__main__":
    main()
