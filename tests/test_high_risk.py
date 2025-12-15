"""
CÓDIGO DE ALTO RIESGO - MÚLTIPLES VULNERABILIDADES CRÍTICAS
Este archivo contiene vulnerabilidades intencionales para probar el modelo
"""

import os
import subprocess
import pickle
import hashlib
from flask import Flask, request

app = Flask(__name__)

# VULNERABILIDAD 1: Contraseña hardcodeada
DATABASE_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"
SECRET_TOKEN = "my_secret_token_12345"

# VULNERABILIDAD 2: SQL Injection
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    # Concatenación directa de SQL con input del usuario
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return cursor.fetchone()

# VULNERABILIDAD 3: Command Injection
@app.route('/ping')
def ping_server():
    host = request.args.get('host')
    # Ejecución de comando shell con input del usuario sin sanitizar
    result = os.system("ping -c 4 " + host)
    return {"result": result}

# VULNERABILIDAD 4: Unsafe Deserialization
@app.route('/load_data')
def load_data():
    data = request.form.get('data')
    # Pickle load de datos no confiables
    obj = pickle.loads(data)
    return {"loaded": obj}

# VULNERABILIDAD 5: Path Traversal
@app.route('/read_file')
def read_file():
    filename = request.args.get('file')
    # Apertura de archivo sin validación
    with open(filename, 'r') as f:
        content = f.read()
    return content

# VULNERABILIDAD 6: Weak Cryptography
def hash_password(password):
    # Uso de MD5 (algoritmo débil)
    return hashlib.md5(password.encode()).hexdigest()

# VULNERABILIDAD 7: Eval con input de usuario
@app.route('/calculate')
def calculate():
    expression = request.args.get('expr')
    # Uso de eval con input del usuario
    result = eval(expression)
    return {"result": result}

# VULNERABILIDAD 8: Shell=True en subprocess
@app.route('/backup')
def backup_database():
    table = request.args.get('table')
    # Uso de shell=True con concatenación
    subprocess.call("mysqldump -u root " + table, shell=True)
    return {"status": "backup completed"}

# VULNERABILIDAD 9: Debug mode habilitado
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

# VULNERABILIDAD 10: XSS - Reflected
@app.route('/greet')
def greet():
    name = request.args.get('name')
    # Retorno de input sin sanitizar
    return f"<h1>Hello {name}!</h1>"

# VULNERABILIDAD 11: Random inseguro para tokens
import random
def generate_session_token():
    return str(random.randint(100000, 999999))

# VULNERABILIDAD 12: Exec con string dinámico
def execute_code(code_string):
    exec(code_string)
    return "executed"

# Complejidad ciclomática alta
def complex_function(a, b, c, d, e):
    if a > 0:
        if b > 0:
            if c > 0:
                if d > 0:
                    if e > 0:
                        for i in range(a):
                            for j in range(b):
                                if i % 2 == 0:
                                    if j % 3 == 0:
                                        print("nested")
    return True