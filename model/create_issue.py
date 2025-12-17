import json

SUMMARY = "reports/ci_summary.json"

def main():
    issue_lines = []
    issue_lines.append("# 🚨 Riesgos detectados en Pull Request\n")
    
    with open(SUMMARY, "r") as f:
        risks = json.load(f)

    for r in risks:
        issue_lines.append(f"- `{r['file']}` → **{r['verdict']}** ({r['score']*100:.1f}%)")
        issue_lines.append("")

    print("\n".join(issue_lines))

if __name__ == "__main__":
    main()
