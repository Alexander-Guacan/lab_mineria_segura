import os
import sys
import json
import requests
from datetime import datetime

# ---------------------------------------------------------
# CONFIG
# ---------------------------------------------------------
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

if not BOT_TOKEN or not CHAT_ID:
    print("❌ ERROR: Variables TELEGRAM_BOT_TOKEN o TELEGRAM_CHAT_ID no definidas")
    sys.exit(1)

# ---------------------------------------------------------
# UTILIDAD DE ENVÍO
# ---------------------------------------------------------
def send_message(text):
    payload = {
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": False
    }
    r = requests.post(TELEGRAM_API, json=payload)
    if r.status_code != 200:
        print("❌ Error enviando mensaje a Telegram:", r.text)

# ---------------------------------------------------------
# MENSAJES POR TIPO
# ---------------------------------------------------------
def notify_stage_start(stage_name):
    msg = f"""
🚀 <b>Inicio de Pipeline</b>
📌 <b>Etapa:</b> {stage_name}
🕒 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    send_message(msg.strip())

def notify_stage_success(stage_name):
    msg = f"""
✅ <b>Etapa completada</b>
📌 <b>Etapa:</b> {stage_name}
🕒 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    send_message(msg.strip())

def notify_stage_failure(stage_name):
    msg = f"""
❌ <b>Fallo en Pipeline</b>
📌 <b>Etapa:</b> {stage_name}
🕒 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    send_message(msg.strip())

def notify_scan_results(report_path, report_url):
    if not os.path.exists(report_path):
        send_message("⚠️ No se encontró el reporte de seguridad.")
        return

    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    total = len(report)
    critical = high = medium = 0

    for data in report.values():
        if data["verdict"] == "CRITICAL":
            critical += 1
        elif data["verdict"] == "HIGH":
            high += 1
        elif data["verdict"] == "MEDIUM":
            medium += 1

    msg = f"""
🛡️ <b>Resultado de Análisis de Seguridad</b>
📄 Archivos analizados: {total}

🔴 <b>CRITICAL:</b> {critical}
🟠 <b>HIGH:</b> {high}
🟡 <b>MEDIUM:</b> {medium}

📄 <b>Reporte completo:</b>
<a href="{report_url}">{report_url}</a>

📌 El pipeline continuará según la política definida.
"""
    send_message(msg.strip())

def notify_custom(message):
    send_message(message)

# ---------------------------------------------------------
# CLI
# ---------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print("Uso:")
        print("  python notify_telegram.py stage_start <nombre_etapa>")
        print("  python notify_telegram.py stage_success <nombre_etapa>")
        print("  python notify_telegram.py stage_fail <nombre_etapa>")
        print("  python notify_telegram.py scan_result <ruta_reporte> <url_reporte>")
        print("  python notify_telegram.py custom <mensaje>")
        sys.exit(1)

    action = sys.argv[1]

    if action == "stage_start":
        notify_stage_start(sys.argv[2])

    elif action == "stage_success":
        notify_stage_success(sys.argv[2])

    elif action == "stage_fail":
        notify_stage_failure(sys.argv[2])

    elif action == "scan_result":
        notify_scan_results(sys.argv[2], sys.argv[3])

    elif action == "custom":
        notify_custom(" ".join(sys.argv[2:]))

    else:
        print("❌ Acción no reconocida")

if __name__ == "__main__":
    main()
