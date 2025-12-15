"""
CÓDIGO DE BAJO RIESGO - BUENAS PRÁCTICAS DE SEGURIDAD
Este código implementa las mejores prácticas de seguridad
"""

import os
import hashlib
import secrets
import logging
from typing import Optional, Dict, List
from flask import Flask, request, jsonify, escape
from werkzeug.security import generate_password_hash, check_password_hash
import re
from functools import wraps

app = Flask(__name__)

# Configuración segura desde variables de entorno
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
DATABASE_URL = os.getenv('DATABASE_URL')

# Configuración de logging seguro
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SecurityValidator:
    """Clase para validación de entrada de usuario"""
    
    @staticmethod
    def validate_integer(value: str, min_val: int = 0, max_val: int = 999999) -> Optional[int]:
        """Valida que un valor sea un entero dentro de un rango"""
        try:
            int_value = int(value)
            if min_val <= int_value <= max_val:
                return int_value
        except (ValueError, TypeError):
            pass
        return None
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Valida formato de email"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitiza nombres de archivo"""
        # Remover caracteres peligrosos
        safe_name = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
        return safe_name


class DatabaseHandler:
    """Manejador de base de datos con queries parametrizados"""
    
    def __init__(self, connection):
        self.connection = connection
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """Obtiene usuario usando query parametrizado"""
        cursor = self.connection.cursor()
        
        # Query parametrizado para prevenir SQL injection
        query = "SELECT id, username, email FROM users WHERE id = ?"
        cursor.execute(query, (user_id,))
        
        result = cursor.fetchone()
        if result:
            return {
                "id": result[0],
                "username": result[1],
                "email": result[2]
            }
        return None
    
    def create_user(self, username: str, email: str, password: str) -> bool:
        """Crea usuario con password hasheado"""
        cursor = self.connection.cursor()
        
        # Hash seguro del password
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        
        # Query parametrizado
        query = "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)"
        
        try:
            cursor.execute(query, (username, email, password_hash))
            self.connection.commit()
            return True
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            self.connection.rollback()
            return False


class CryptoHelper:
    """Funciones criptográficas seguras"""
    
    @staticmethod
    def generate_token() -> str:
        """Genera token seguro usando secrets"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash seguro de password con salt"""
        return generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    
    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Verifica password contra hash"""
        return check_password_hash(password_hash, password)


def require_auth(f):
    """Decorator para requerir autenticación"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_token = request.headers.get('Authorization')
        
        if not auth_token:
            return jsonify({"error": "Authentication required"}), 401
        
        # Verificar token (implementación simplificada)
        if not verify_token(auth_token):
            return jsonify({"error": "Invalid token"}), 401
        
        return f(*args, **kwargs)
    return decorated_function


def verify_token(token: str) -> bool:
    """Verifica validez del token"""
    # Implementación real usaría JWT o similar
    return len(token) > 10


# Rutas seguras
@app.route('/user/<int:user_id>', methods=['GET'])
@require_auth
def get_user(user_id: int):
    """Obtiene información de usuario de forma segura"""
    
    # Validación del ID
    if user_id <= 0:
        return jsonify({"error": "Invalid user ID"}), 400
    
    try:
        db = DatabaseHandler(get_db_connection())
        user = db.get_user_by_id(user_id)
        
        if user:
            return jsonify(user)
        else:
            return jsonify({"error": "User not found"}), 404
            
    except Exception as e:
        logger.error(f"Error fetching user: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route('/register', methods=['POST'])
def register_user():
    """Registra nuevo usuario de forma segura"""
    
    try:
        data = request.get_json()
        
        # Validación de entrada
        if not all(key in data for key in ['username', 'email', 'password']):
            return jsonify({"error": "Missing required fields"}), 400
        
        # Validar formato de email
        if not SecurityValidator.validate_email(data['email']):
            return jsonify({"error": "Invalid email format"}), 400
        
        # Validar longitud de password
        if len(data['password']) < 8:
            return jsonify({"error": "Password too short"}), 400
        
        # Crear usuario
        db = DatabaseHandler(get_db_connection())
        success = db.create_user(
            username=data['username'],
            email=data['email'],
            password=data['password']
        )
        
        if success:
            return jsonify({"message": "User created successfully"}), 201
        else:
            return jsonify({"error": "Failed to create user"}), 500
            
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route('/files/<filename>', methods=['GET'])
@require_auth
def get_file(filename: str):
    """Lee archivo de forma segura"""
    
    # Sanitizar nombre de archivo
    safe_filename = SecurityValidator.sanitize_filename(filename)
    
    # Directorio base seguro
    base_directory = os.path.abspath('/var/www/safe_uploads')
    file_path = os.path.join(base_directory, safe_filename)
    
    # Prevenir path traversal
    if not file_path.startswith(base_directory):
        return jsonify({"error": "Access denied"}), 403
    
    # Verificar existencia
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({"content": content})
        
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        return jsonify({"error": "Failed to read file"}), 500


def get_db_connection():
    """Obtiene conexión a base de datos (mock)"""
    # Implementación real conectaría a la base de datos
    return None


def process_list(items: List[int]) -> List[int]:
    """Procesa lista de forma simple y segura"""
    return [item * 2 for item in items if isinstance(item, int) and item > 0]


def calculate_statistics(numbers: List[float]) -> Dict[str, float]:
    """Calcula estadísticas de forma segura"""
    
    if not numbers:
        return {"error": "Empty list"}
    
    # Validar que todos son números
    if not all(isinstance(n, (int, float)) for n in numbers):
        return {"error": "Invalid input"}
    
    return {
        "count": len(numbers),
        "sum": sum(numbers),
        "average": sum(numbers) / len(numbers),
        "min": min(numbers),
        "max": max(numbers)
    }


# Configuración de producción segura
if __name__ == '__main__':
    # Debug SIEMPRE deshabilitado
    # Host restringido a localhost
    # Puerto no privilegiado
    app.run(
        debug=False,
        host='127.0.0.1',
        port=5000
    )