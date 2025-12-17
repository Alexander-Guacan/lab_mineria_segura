# src/ci_check.py
import json
import sys

REPORT = "reports/multilang_security_report.json"

RISK_THRESHOLD = 0.7
BLOCKING_VERDICTS = ["CRITICAL"]

def main():
    with open(REPORT, "r", encoding="utf-8") as f:
        report = json.load(f)

    risky_files = []

    for file, data in report.items():
        if data["verdict"] in BLOCKING_VERDICTS or data["score"] >= RISK_THRESHOLD:
            risky_files.append({
                "file": file,
                "verdict": data["verdict"],
                "score": data["score"]
            })

    if risky_files:
        print("❌ Riesgos detectados:")
        for r in risky_files:
            print(f" - {r['file']} → {r['verdict']} ({r['score']*100:.1f}%)")

        # Guardamos resumen para issue / telegram
        with open("reports/ci_summary.json", "w") as f:
            json.dump(risky_files, f, indent=4)

        sys.exit(1)  # ❌ bloquea el PR

    print("✅ No se detectaron riesgos críticos")
    sys.exit(0)

if __name__ == "__main__":
    main()
