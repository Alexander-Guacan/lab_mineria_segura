import json
import os
import sys

# Colores para la consola
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

REPORT_FILE = "multilang_security_report.json"

def print_dashboard():
    if not os.path.exists(REPORT_FILE):
        print("No se encuentra el reporte. Ejecuta step4 primero.")
        return

    with open(REPORT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    print(f"\n{Colors.HEADER}{'='*80}")
    print(f" REPORTE DE AUDITORÍA DE SEGURIDAD (IA + STATIC ANALYSIS)")
    print(f"{'='*80}{Colors.ENDC}\n")

    for filename, report in data.items():
        verdict = report.get("verdict", "UNKNOWN")
        prob = report.get("ml_prob", 0)
        findings = report.get("findings", [])
        
        # Determinar color según veredicto
        if verdict in ["CRITICAL", "HIGH"]:
            color = Colors.FAIL
            icon = "🔴"
        elif verdict in ["MEDIUM"]:
            color = Colors.WARNING
            icon = "🟠"
        else:
            color = Colors.GREEN
            icon = "🟢"

        print(f"{Colors.BOLD}ARCHIVO: {filename}{Colors.ENDC}")
        print(f"  Veredicto: {color}{icon} {verdict}{Colors.ENDC}")
        print(f"  Confianza IA: {prob:.2%}")
        
        if findings:
            print(f"  {Colors.WARNING}Hallazgos ({len(findings)}):{Colors.ENDC}")
            print(f"  {'-'*60}")
            print(f"  {'LÍNEA':<6} | {'SEVERIDAD':<10} | {'TIPO':<25} | {'DETALLE'}")
            print(f"  {'-'*60}")
            
            for f in findings:
                line = str(f['line'])
                sev = f['severity']
                name = f['type']
                snippet = f.get('snippet', '')
                detail = (snippet[:40] + '..') if len(snippet) > 40 else snippet
                
                sev_color = Colors.FAIL if sev in ["CRITICAL", "HIGH"] else Colors.WARNING
                
                print(f"  {line:<6} | {sev_color}{sev:<10}{Colors.ENDC} | {name:<25} | {detail}")
                 
                if snippet and len(snippet) > 40:
                    print(f"         {Colors.BLUE}└── Código completo: {snippet}{Colors.ENDC}")
            print("\n")
        else:
            print(f"  {Colors.GREEN}✔ No se detectaron vulnerabilidades conocidas.{Colors.ENDC}\n")
        
        print(f"{'-'*80}")

if __name__ == "__main__":
    # Soporte para colores en Windows antiguo
    os.system('color')
    print_dashboard()