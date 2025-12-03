from flask import Flask, request
import sqlite3
import os

app = Flask(__name__)

# ❌ Secret key insegura y hardcodeada
app.secret_key = "insecure_secret_key"

DB_PATH = "database.db"

# Inicializa DB mínima
def init_db():
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
        c.execute("INSERT INTO users (name) VALUES ('Alice')")
        c.execute("INSERT INTO users (name) VALUES ('Bob')")
        conn.commit()
        conn.close()

# ❌ Vulnerabilidad: SQL Injection
@app.route("/user")
def get_user():
    name = request.args.get("name", "")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Totalmente inseguro: se concatena la entrada del usuario
    query = f"SELECT * FROM users WHERE name = '{name}'"
    print("Ejecutando SQL:", query)

    try:
        result = c.execute(query).fetchall()
    except Exception as e:
        result = []

    conn.close()
    return str(result)

# ❌ Vulnerabilidad: XSS reflejado (aunque sin templates)
@app.route("/hello")
def hello():
    user = request.args.get("user", "Invitado")
    return f"Hola {user}"  # sin sanitizar

# ❌ Vuln: ejecución de comandos del sistema (Command Injection)
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # Muy inseguro: input directo en el shell
    cmd = f"ping -c 1 {host}"
    print("Ejecutando comando:", cmd)
    stream = os.popen(cmd)
    output = stream.read()
    return output

# ❌ Vuln: Escritura de archivos sin validación (Path Traversal)
@app.route("/save", methods=["POST"])
def save():
    filename = request.args.get("file", "default.txt")
    content = request.data.decode("utf-8")
    with open(filename, "w") as f:  # el usuario controla filename
        f.write(content)
    return "Guardado"

# ❌ Debug mode activado
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
