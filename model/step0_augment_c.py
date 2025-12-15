import pandas as pd
import random
import os

# RUTA DEL DATASET PARTICIONADO DE C
TARGET_CSV = "data/partitioned/dataset_c_cpp.csv"
# AUMENTAMOS DRÁSTICAMENTE LA CANTIDAD PARA DOMINAR EL RUIDO
NUM_SAMPLES = 15000 

templates = [
    # 1. BUFFER OVERFLOW (strcpy vs strncpy)
    { "type": 1, "code": "void {func}(char *in) {{ char buf[{size}]; strcpy(buf, in); }}" },
    { "type": 0, "code": "void {func}(char *in) {{ char buf[{size}]; strncpy(buf, in, {size}-1); }}" },
    
    # 2. COMMAND INJECTION (system)
    { "type": 1, "code": "void {func}(char *arg) {{ char cmd[256]; sprintf(cmd, \"cat %s\", arg); system(cmd); }}" },
    { "type": 0, "code": "void {func}(char *arg) {{ char *args[] = {{\"cat\", arg, NULL}}; execvp(args[0], args); }}" },
    
    # 3. FORMAT STRING (printf)
    { "type": 1, "code": "void {func}(char *user_data) {{ printf(user_data); }}" },
    { "type": 0, "code": "void {func}(char *user_data) {{ printf(\"%s\", user_data); }}" },
    
    # 4. INTEGER OVERFLOW (malloc)
    { "type": 1, "code": "void {func}(int n) {{ char *p = malloc(n * sizeof(char)); }}" },
    { "type": 0, "code": "void {func}(int n) {{ if(n > 0 && n < MAX) {{ char *p = malloc(n * sizeof(char)); }} }}" },

    # 5. GETS (Siempre vulnerable)
    { "type": 1, "code": "void {func}() {{ char buf[100]; gets(buf); }}" },
    { "type": 0, "code": "void {func}() {{ char buf[100]; fgets(buf, 100, stdin); }}" }
]

def generate_massive_c_data():
    print(f"--- GENERANDO INYECCIÓN MASIVA PARA C/C++ ({NUM_SAMPLES} muestras) ---")
    
    vocab_func = ["handle_req", "parse_input", "log_error", "copy_mem", "run_cmd", "init_service"]
    vocab_size = ["64", "128", "256", "512", "1024"]
    
    new_data = []
    
    for _ in range(NUM_SAMPLES):
        tmpl = random.choice(templates)
        # Randomizamos nombres para que no sean idénticos
        func_name = random.choice(vocab_func) + "_" + str(random.randint(1000, 9999))
        size_val = random.choice(vocab_size)
        
        code = tmpl["code"].format(func=func_name, size=size_val)
        new_data.append({"code": code, "target": tmpl["type"]})

    # Cargar dataset existente
    if os.path.exists(TARGET_CSV):
        print("Cargando dataset existente...")
        df_old = pd.read_csv(TARGET_CSV)
        print(f"Original (Ruidoso): {len(df_old)} filas")
        
        # Fusión: Sintético (Limpio) + Original (Ruidoso)
        df_new = pd.DataFrame(new_data)
        df_final = pd.concat([df_old, df_new], ignore_index=True)
        
        # Eliminar duplicados para evitar sobrepeso exacto
        df_final = df_final.drop_duplicates(subset=['code'])
        
        df_final.to_csv(TARGET_CSV, index=False)
        print(f"✅ Dataset C/C++ Actualizado. Total: {len(df_final)} filas.")
        print("   (Ahora los datos limpios son mayoría)")
    else:
        print(f"❌ Error: No encuentro {TARGET_CSV}.")

if __name__ == "__main__":
    generate_massive_c_data()