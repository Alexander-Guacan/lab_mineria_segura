"""
Archivo con MÚLTIPLES VULNERABILIDADES de seguridad
NO usar en producción - Solo para testing
"""

import os
import pickle
import subprocess
import sqlite3

# Vulnerabilidad 1: SQL Injection
def buscar_usuario(username):
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    # SQL Injection - concatenación directa
    query = f"SELECT * FROM usuarios WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

# Vulnerabilidad 2: Command Injection
def ejecutar_comando(filename):
    # Command injection - uso directo de input del usuario
    os.system(f"cat {filename}")
    subprocess.call("ls -la " + filename, shell=True)

# Vulnerabilidad 3: Path Traversal
def leer_archivo(ruta):
    # No valida la ruta, permite acceso a cualquier archivo
    with open(ruta, 'r') as f:
        return f.read()

# Vulnerabilidad 4: Deserialización insegura
def cargar_datos(data):
    # Pickle es inseguro con datos no confiables
    return pickle.loads(data)

# Vulnerabilidad 5: Hardcoded credentials
DB_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"
SECRET_TOKEN = "mi_token_super_secreto"

# Vulnerabilidad 6: Weak cryptography
def encriptar_password(password):
    # MD5 es débil para passwords
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()

# Vulnerabilidad 7: eval() con input del usuario
def calcular(expresion):
    # eval es extremadamente peligroso
    return eval(expresion)

# Vulnerabilidad 8: Información sensible en logs
def login(username, password):
    print(f"Login attempt: {username} con password: {password}")
    if password == "admin123":
        return True
    return False

# Vulnerabilidad 9: XXE (XML External Entity)
def procesar_xml(xml_string):
    import xml.etree.ElementTree as ET
    # Vulnerable a XXE attacks
    root = ET.fromstring(xml_string)
    return root

# Vulnerabilidad 10: Race condition
temp_file = "/tmp/datos.txt"
def escribir_y_leer():
    with open(temp_file, 'w') as f:
        f.write("datos sensibles")
    # Race condition aquí
    with open(temp_file, 'r') as f:
        return f.read()

# Vulnerabilidad 11: Sin validación de tipos
def procesar_edad(edad):
    # No valida que sea número, puede causar crashes
    return edad + 10

# Vulnerabilidad 12: SSRF (Server Side Request Forgery)
def obtener_url(url):
    import urllib.request
    # No valida la URL, permite SSRF
    response = urllib.request.urlopen(url)
    return response.read()

# Vulnerabilidad 13: Permisos inseguros
def crear_archivo_config():
    with open('config.conf', 'w') as f:
        f.write(f"password={DB_PASSWORD}")
    os.chmod('config.conf', 0o777)  # Permisos muy permisivos

# Vulnerabilidad 14: No manejo de excepciones
def dividir(a, b):
    return a / b  # Puede causar ZeroDivisionError

# Vulnerabilidad 15: Uso de assert para validación
def validar_admin(user):
    assert user == "admin", "No es admin"
    # assert puede ser deshabilitado con -O
    return True

if __name__ == "__main__":
    # Código de prueba vulnerable
    user_input = input("Ingrese comando: ")
    ejecutar_comando(user_input)