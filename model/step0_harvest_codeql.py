import os
import shutil
import subprocess
import pandas as pd

# CONFIGURACIÓN
REPO_URL = "https://github.com/github/codeql.git"
TEMP_DIR = "temp_codeql_js"
OUTPUT_CSV = "data/partitioned/dataset_js_codeql.csv"

# Solo nos interesan las pruebas de seguridad de JS
TARGET_SUBDIR = "javascript/ql/test/query-tests/Security"

def harvest_codeql():
    print("--- COSECHANDO DATOS DE GITHUB CODEQL (JS/TS) ---")
    
    # 1. CLONAR (Usamos sparse-checkout para no bajar todo el repo que es gigante)
    if os.path.exists(TEMP_DIR):
        try: shutil.rmtree(TEMP_DIR)
        except: pass

    os.makedirs(TEMP_DIR, exist_ok=True)
    
    print("Iniciando clonado parcial (Sparse Checkout)...")
    # Nota: Esto requiere Git >= 2.25. Si falla, clonará todo (más lento).
    try:
        subprocess.run(["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse", REPO_URL, TEMP_DIR], check=True)
        os.chdir(TEMP_DIR)
        subprocess.run(["git", "sparse-checkout", "set", TARGET_SUBDIR], check=True)
        os.chdir("..")
    except Exception as e:
        print(f"⚠️ Alerta: Falló el clonado optimizado ({e}). Intentando clonado normal (lento)...")
        if os.path.exists(TEMP_DIR): shutil.rmtree(TEMP_DIR)
        subprocess.run(["git", "clone", "--depth", "1", REPO_URL, TEMP_DIR], check=True)

    # 2. ESCANEAR ARCHIVOS
    print(f"Escaneando {TARGET_SUBDIR}...")
    
    data = []
    scan_path = os.path.join(TEMP_DIR, TARGET_SUBDIR)
    
    if not os.path.exists(scan_path):
        print(f"❌ Error: No se encontró la ruta {scan_path}")
        return

    for root, dirs, files in os.walk(scan_path):
        for file in files:
            if file.endswith((".js", ".ts", ".jsx", ".tsx")):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                except:
                    continue

                # LÓGICA DE EXTRACCIÓN CODEQL
                # CodeQL suele marcar las líneas vulnerables con comentarios como:
                # "NOT OK", "BAD", "Unsafe", "Vulnerable"
                # Y las seguras con "OK", "GOOD", "Safe"
                
                for i, line in enumerate(lines):
                    content = line.strip()
                    if len(content) < 5 or content.startswith(("*", "//", "/*")): 
                        continue # Ignorar comentarios puros

                    lower_line = line.lower()
                    
                    # Heurística de CodeQL
                    is_vuln = any(x in lower_line for x in ["// bad", "// not ok", "// unsafe", "// flaw"])
                    is_safe = any(x in lower_line for x in ["// good", "// ok", "// safe", "// fixed"])

                    if is_vuln:
                        # Limpiamos el comentario para que el modelo no haga trampa
                        clean_code = line.split("//")[0].strip()
                        if clean_code:
                            data.append({"code": clean_code, "target": 1, "source": "codeql"})
                    
                    elif is_safe:
                        clean_code = line.split("//")[0].strip()
                        if clean_code:
                            data.append({"code": clean_code, "target": 0, "source": "codeql"})

    # 3. GUARDAR
    if data:
        df = pd.DataFrame(data)
        df = df.drop_duplicates(subset=['code'])
        # Filtrar códigos triviales
        df = df[df['code'].str.len() > 10]
        
        os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
        df.to_csv(OUTPUT_CSV, index=False)
        
        print(f"\n✅ ÉXITO: Se extrajeron {len(df)} muestras de CodeQL.")
        print(f"   Vulnerables: {df['target'].sum()}")
        print(f"   Seguros: {len(df) - df['target'].sum()}")
        print(f"   Guardado en: {OUTPUT_CSV}")
    else:
        print("❌ No se encontraron datos. Algo falló en la búsqueda.")

    # Limpieza
    try:
        shutil.rmtree(TEMP_DIR)
        print("Archivos temporales eliminados.")
    except: pass

if __name__ == "__main__":
    harvest_codeql()