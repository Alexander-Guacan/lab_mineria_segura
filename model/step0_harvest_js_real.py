import os
import re
import pandas as pd
import shutil
import subprocess

# CONFIGURACIÓN
REPO_URL = "https://github.com/semgrep/semgrep-rules.git"
TEMP_DIR = "temp_semgrep_rules"
OUTPUT_CSV = "data/partitioned/dataset_js_real.csv"

def harvest_semgrep_data():
    print("--- COSECHANDO DATOS REALES DE SEMGREP RULES (JS/TS) ---")
    
    # 1. CLONAR REPOSITORIO
    if os.path.exists(TEMP_DIR):
        print(f"Limpiando directorio temporal {TEMP_DIR}...")
        try:
            shutil.rmtree(TEMP_DIR) # Forzamos limpieza para actualizar
        except:
            pass # A veces Windows bloquea archivos, continuamos si no podemos borrar

    # Si no existe (o si falló el borrado parcial), intentamos clonar
    if not os.path.exists(TEMP_DIR):
        print(f"Clonando {REPO_URL} (esto puede tardar unos segundos)...")
        try:
            subprocess.run(["git", "clone", "--depth", "1", REPO_URL, TEMP_DIR], check=True)
        except FileNotFoundError:
            print("❌ Error: No tienes 'git' instalado en tu terminal.")
            print("Instala Git o descarga el ZIP manualmente.")
            return

    # 2. RECORRER ARCHIVOS Y EXTRAER CÓDIGO
    print("Escaneando archivos de prueba...")
    
    data = []
    # Buscamos en carpetas de javascript y typescript
    target_dirs = [
        os.path.join(TEMP_DIR, "javascript"),
        os.path.join(TEMP_DIR, "typescript")
    ]
    
    for target_dir in target_dirs:
        if not os.path.exists(target_dir): continue
        
        for root, dirs, files in os.walk(target_dir):
            for file in files:
                if file.endswith((".js", ".ts", ".jsx", ".tsx")):
                    filepath = os.path.join(root, file)
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                    
                    # LÓGICA DE EXTRACCIÓN
                    # Semgrep usa comentarios:
                    # // ruleid: nombre-regla  <-- La línea anterior o siguiente es VULNERABLE
                    # // ok: nombre-regla      <-- La línea anterior o siguiente es SEGURA
                    
                    for i, line in enumerate(lines):
                        line_clean = line.strip()
                        
                        # CASO 1: VULNERABLE
                        if "ruleid:" in line_clean:
                            # A veces el código está en la misma línea antes del comentario
                            code_part = line.split("//")[0].strip()
                            if len(code_part) > 5:
                                data.append({"code": code_part, "target": 1, "source": "semgrep_real"})
                            # A veces el código está en la línea siguiente (si la actual es solo comentario)
                            elif i + 1 < len(lines):
                                next_line = lines[i+1].strip()
                                if next_line and not next_line.startswith("//"):
                                    data.append({"code": next_line, "target": 1, "source": "semgrep_real"})

                        # CASO 2: SEGURO
                        if "ok:" in line_clean:
                            code_part = line.split("//")[0].strip()
                            if len(code_part) > 5:
                                data.append({"code": code_part, "target": 0, "source": "semgrep_real"})
                            elif i + 1 < len(lines):
                                next_line = lines[i+1].strip()
                                if next_line and not next_line.startswith("//"):
                                    data.append({"code": next_line, "target": 0, "source": "semgrep_real"})

    # 3. GUARDAR
    if data:
        df = pd.DataFrame(data)
        # Limpieza de duplicados
        df = df.drop_duplicates(subset=['code'])
        # Filtrar líneas muy cortas o irrelevantes
        df = df[df['code'].str.len() > 10]
        
        os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
        df.to_csv(OUTPUT_CSV, index=False)
        
        print(f"✅ ÉXITO: Se extrajeron {len(df)} muestras reales.")
        print(f"   Vulnerables: {df['target'].sum()}")
        print(f"   Seguros: {len(df) - df['target'].sum()}")
        print(f"   Guardado en: {OUTPUT_CSV}")
        
        # Limpieza final
        # shutil.rmtree(TEMP_DIR) 
    else:
        print("⚠️ No se encontraron patrones. Revisa si se clonó bien el repo.")

if __name__ == "__main__":
    harvest_semgrep_data()