import os
import pickle
import hashlib

# --- Vulnerabilidad 1: Credenciales hardcodeadas ---
DB_PASSWORD = "SuperSecreto123"   # Hardcoded password

# --- Vulnerabilidad 2: Inyección de comandos ---
def list_directory(path):
    # Peligroso: concatena entrada del usuario directamente en el comando
    os.system("ls -la " + path)

# --- Vulnerabilidad 3: Deserialización insegura ---
def load_user_data(file_path):
    # Peligroso: carga datos pickle sin validación
    with open(file_path, "rb") as f:
        data = pickle.load(f)  # Puede ejecutar código arbitrario
    return data

# --- Vulnerabilidad 4: Hash inseguro ---
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # MD5 inseguro

# --- Vulnerabilidad 5: Manejo deficiente de errores ---
def divide(a, b):
    try:
        return a / b
    except:
        # Captura genérica que oculta errores
        return "Error!"

# --- Vulnerabilidad 6: Validación insuficiente de inputs ---
def get_user_age():
    age = input("Ingresa tu edad: ")   # Sin validar
    return int(age)                    # Puede explotar con datos no numéricos

# --- Vulnerabilidad 7: Escritura insegura en archivo ---
def save_log(message):
    with open("/tmp/app.log", "a") as f:
        f.write(message + "\n")        # No sanitiza contenido

# --- Programa principal ---
if __name__ == "__main__":
    print("=== Demo de código con vulnerabilidades (para análisis) ===")
    
    path = input("Directorio a listar: ")
    list_directory(path)

    print("Hash inseguro de contraseña 'test':", hash_password("test"))

    try:
        data = load_user_data("user_data.pkl")
        print("Datos cargados:", data)
    except Exception as e:
        print("Error cargando datos:", e)

    print("Resultado división:", divide(10, 0))

    age = get_user_age()
    print("Tu edad es:", age)

    save_log("Usuario consultó el sistema.")
