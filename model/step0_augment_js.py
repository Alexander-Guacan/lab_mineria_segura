import pandas as pd
import random
import os

# RUTA DONDE SE GUARDARÁ EL DATASET
OUTPUT_CSV = "data/partitioned/dataset_js.csv"
INPUT_CVE = "data/cvefixes/raw/CVEFixes.csv"
NUM_SAMPLES = 10000 

# PLANTILLAS DE VULNERABILIDADES JS (Frontend y Node.js)
templates = [
    # 1. DOM XSS (innerHTML vs textContent)
    { "type": 1, "code": "function updateUI(userInput) {{ const el = document.getElementById('msg'); el.innerHTML = userInput; }}" },
    { "type": 0, "code": "function updateUI(userInput) {{ const el = document.getElementById('msg'); el.textContent = userInput; }}" },

    # 2. EVAL INJECTION (Node.js/Browser)
    { "type": 1, "code": "function calc(expr) {{ const result = eval(expr); return result; }}" },
    { "type": 0, "code": "function calc(expr) {{ const result = parseInt(expr); return result; }}" },

    # 3. COMMAND INJECTION (Node.js child_process)
    { "type": 1, "code": "const { exec } = require('child_process'); function run(cmd) {{ exec('ls ' + cmd, (err)=>{{}}); }}" },
    { "type": 0, "code": "const { execFile } = require('child_process'); function run(arg) {{ execFile('ls', [arg], (err)=>{{}}); }}" },

    # 4. PROTOTYPE POLLUTION (Assignment)
    { "type": 1, "code": "function merge(target, input) {{ for (let key in input) {{ target[key] = input[key]; }} }}" },
    { "type": 0, "code": "function merge(target, input) {{ for (let key in input) {{ if (key !== '__proto__') target[key] = input[key]; }} }}" },

    # 5. REFLECTED XSS (Express.js)
    { "type": 1, "code": "app.get('/search', (req, res) => {{ res.send('Results for: ' + req.query.q); }});" },
    { "type": 0, "code": "app.get('/search', (req, res) => {{ res.send('Results for: ' + escapeHTML(req.query.q)); }});" }
]

def generate_js_dataset():
    print(f"--- GENERANDO DATASET JAVASCRIPT ({NUM_SAMPLES} sintéticos + Reales) ---")
    
    # 1. Generar Sintéticos
    vocab_func = ["render", "init", "handleRequest", "processData", "loadConfig"]
    new_data = []
    
    for _ in range(NUM_SAMPLES):
        tmpl = random.choice(templates)
        # Variaciones simples
        func_name = random.choice(vocab_func) + "_" + str(random.randint(100, 999))
        code = tmpl["code"].replace("function ", f"function {func_name}").replace("const ", f"const v{random.randint(1,99)} = ")
        new_data.append({"code": code, "target": tmpl["type"]})

    df_synthetic = pd.DataFrame(new_data)
    
    # 2. Extraer Reales de CVEFixes (Si existen)
    df_real = pd.DataFrame()
    if os.path.exists(INPUT_CVE):
        print("Buscando muestras reales en CVEFixes...")
        df_cve = pd.read_csv(INPUT_CVE)
        # Filtramos JS (a veces aparece como 'js', 'javascript' o 'ts')
        mask = df_cve['language'].astype(str).str.lower().isin(['js', 'javascript', 'ts', 'typescript'])
        df_real = df_cve[mask].copy()
        
        if not df_real.empty:
            df_real['target'] = df_real['safety'].apply(lambda x: 1 if x == 'vulnerable' else 0)
            df_real = df_real[['code', 'target']]
            print(f" -> Encontradas {len(df_real)} muestras reales.")
    
    # 3. Fusión
    df_final = pd.concat([df_real, df_synthetic], ignore_index=True)
    df_final = df_final.drop_duplicates(subset=['code'])
    
    # Guardar
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    df_final.to_csv(OUTPUT_CSV, index=False)
    print(f"✅ Dataset JS creado en: {OUTPUT_CSV}")
    print(f"   Total muestras: {len(df_final)}")

if __name__ == "__main__":
    generate_js_dataset()