"""
Archivo con CÓDIGO SEGURO siguiendo mejores prácticas
Implementa múltiples capas de seguridad
"""

import os
import sqlite3
import hashlib
import secrets
import hmac
import logging
from pathlib import Path
from typing import Optional, Dict, Any
import re
from datetime import datetime, timedelta
import ipaddress

# Configuración segura de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SecureConfig:
    """Gestión segura de configuración"""
    
    def __init__(self):
        self._config = {}
        self._load_config()
    
    def _load_config(self):
        """Carga configuración de forma segura"""
        # En producción, usar servicios como AWS Secrets Manager, Vault, etc.
        config_file = os.getenv('CONFIG_FILE', '/etc/app/config.secure')
        
        if not Path(config_file).exists():
            logger.warning("Archivo de configuración no encontrado")
            return
        
        # Verifica permisos del archivo
        file_stat = os.stat(config_file)
        if file_stat.st_mode & 0o077:
            raise PermissionError("Archivo de configuración tiene permisos inseguros")
        
        # Carga y parsea de forma segura
        with open(config_file, 'r') as f:
            # Aquí usarías un parser seguro como toml o yaml con safe_load
            pass
    
    def get(self, key: str) -> Optional[str]:
        """Obtiene valor de configuración de forma segura"""
        return self._config.get(key)

class SecureDatabase:
    """Operaciones seguras de base de datos"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._connection = None
    
    def __enter__(self):
        self._connection = sqlite3.connect(self.db_path)
        # Configuración segura de SQLite
        self._connection.execute("PRAGMA foreign_keys = ON")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._connection:
            self._connection.close()
    
    def buscar_usuario(self, username: str) -> Optional[Dict[str, Any]]:
        """Búsqueda segura con prepared statements y validación"""
        
        # Validación de entrada
        if not self._validar_username(username):
            logger.warning(f"Intento de búsqueda con username inválido")
            return None
        
        cursor = self._connection.cursor()
        
        try:
            # Prepared statement para prevenir SQL injection
            cursor.execute(
                "SELECT id, username, email, created_at FROM usuarios WHERE username = ?",
                (username,)
            )
            result = cursor.fetchone()
            
            if result:
                return {
                    'id': result[0],
                    'username': result[1],
                    'email': result[2],
                    'created_at': result[3]
                }
            return None
            
        except sqlite3.Error as e:
            logger.error(f"Error en consulta de base de datos: {type(e).__name__}")
            raise
    
    @staticmethod
    def _validar_username(username: str) -> bool:
        """Valida formato de username"""
        if not username or len(username) > 50:
            return False
        # Solo alfanuméricos, guiones y guiones bajos
        return bool(re.match(r'^[a-zA-Z0-9_-]+$', username))

class SecureFileHandler:
    """Manejo seguro de archivos"""
    
    def __init__(self, base_directory: str):
        self.base_dir = Path(base_directory).resolve()
        
        # Verifica que el directorio base existe y es un directorio
        if not self.base_dir.exists():
            raise ValueError(f"Directorio base no existe: {self.base_dir}")
        
        if not self.base_dir.is_dir():
            raise ValueError(f"Ruta base no es un directorio: {self.base_dir}")
    
    def leer_archivo(self, filename: str) -> Optional[str]:
        """Lee archivo de forma segura previniendo path traversal"""
        
        # Validación de nombre de archivo
        if not self._validar_filename(filename):
            logger.warning(f"Intento de acceso con filename inválido: {filename}")
            raise ValueError("Nombre de archivo inválido")
        
        # Construye y resuelve la ruta completa
        file_path = (self.base_dir / filename).resolve()
        
        # Verifica que la ruta resuelta está dentro del directorio base
        if not str(file_path).startswith(str(self.base_dir)):
            logger.warning(f"Intento de path traversal detectado: {filename}")
            raise PermissionError("Acceso fuera del directorio permitido")
        
        # Verifica que el archivo existe y es realmente un archivo
        if not file_path.exists():
            raise FileNotFoundError(f"Archivo no encontrado: {filename}")
        
        if not file_path.is_file():
            raise ValueError(f"La ruta no es un archivo: {filename}")
        
        # Lee el archivo de forma segura
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error leyendo archivo: {type(e).__name__}")
            raise
    
    @staticmethod
    def _validar_filename(filename: str) -> bool:
        """Valida que el nombre de archivo es seguro"""
        if not filename or len(filename) > 255:
            return False
        
        # No permitir caracteres peligrosos
        caracteres_prohibidos = ['..', '/', '\\', '\0', '\n', '\r']
        if any(char in filename for char in caracteres_prohibidos):
            return False
        
        # Solo permitir ciertos caracteres
        return bool(re.match(r'^[a-zA-Z0-9._-]+$', filename))
    
    def escribir_archivo(self, filename: str, content: str) -> None:
        """Escribe archivo con permisos seguros"""
        
        if not self._validar_filename(filename):
            raise ValueError("Nombre de archivo inválido")
        
        file_path = (self.base_dir / filename).resolve()
        
        if not str(file_path).startswith(str(self.base_dir)):
            raise PermissionError("Acceso fuera del directorio permitido")
        
        # Crea archivo con permisos restrictivos
        old_umask = os.umask(0o077)
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
        finally:
            os.umask(old_umask)

class SecurePasswordHandler:
    """Manejo seguro de contraseñas"""
    
    @staticmethod
    def hash_password(password: str) -> bytes:
        """Hash seguro de contraseña usando bcrypt"""
        import bcrypt
        
        # Validación de contraseña
        if not password or len(password) < 8:
            raise ValueError("Contraseña no cumple requisitos mínimos")
        
        # bcrypt con rounds suficientes (12-14 recomendado)
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt)
    
    @staticmethod
    def verificar_password(password: str, hashed: bytes) -> bool:
        """Verifica contraseña de forma segura (resistente a timing attacks)"""
        import bcrypt
        
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed)
        except Exception as e:
            logger.error(f"Error verificando contraseña: {type(e).__name__}")
            return False
    
    @staticmethod
    def generar_token_seguro(length: int = 32) -> str:
        """Genera token criptográficamente seguro"""
        return secrets.token_urlsafe(length)

class SecureAuthentication:
    """Sistema de autenticación seguro"""
    
    def __init__(self):
        self.intentos_fallidos = {}
        self.max_intentos = 5
        self.tiempo_bloqueo = timedelta(minutes=15)
    
    def login(self, username: str, password: str) -> bool:
        """Login seguro con rate limiting y logging apropiado"""
        
        # Verifica si el usuario está bloqueado
        if self._esta_bloqueado(username):
            logger.warning(f"Intento de login en cuenta bloqueada: {username}")
            return False
        
        # Log seguro (NO incluye password)
        logger.info(f"Intento de login para usuario: {username}")
        
        # Verifica credenciales
        with SecureDatabase('usuarios.db') as db:
            usuario = db.buscar_usuario(username)
            
            if not usuario:
                self._registrar_intento_fallido(username)
                return False
            
            # Obtiene hash almacenado (en producción, desde DB)
            stored_hash = self._obtener_hash_almacenado(usuario['id'])
            
            if SecurePasswordHandler.verificar_password(password, stored_hash):
                self._limpiar_intentos_fallidos(username)
                logger.info(f"Login exitoso para usuario: {username}")
                return True
            else:
                self._registrar_intento_fallido(username)
                return False
    
    def _esta_bloqueado(self, username: str) -> bool:
        """Verifica si el usuario está bloqueado por intentos fallidos"""
        if username not in self.intentos_fallidos:
            return False
        
        info = self.intentos_fallidos[username]
        
        # Si han pasado más de tiempo_bloqueo, desbloquea
        if datetime.now() - info['ultimo_intento'] > self.tiempo_bloqueo:
            self._limpiar_intentos_fallidos(username)
            return False
        
        return info['intentos'] >= self.max_intentos
    
    def _registrar_intento_fallido(self, username: str):
        """Registra intento de login fallido"""
        if username not in self.intentos_fallidos:
            self.intentos_fallidos[username] = {'intentos': 0, 'ultimo_intento': datetime.now()}
        
        self.intentos_fallidos[username]['intentos'] += 1
        self.intentos_fallidos[username]['ultimo_intento'] = datetime.now()
    
    def _limpiar_intentos_fallidos(self, username: str):
        """Limpia intentos fallidos después de login exitoso"""
        if username in self.intentos_fallidos:
            del self.intentos_fallidos[username]
    
    @staticmethod
    def _obtener_hash_almacenado(user_id: int) -> bytes:
        """Obtiene hash de contraseña almacenado (simulado)"""
        # En producción, obtener desde base de datos
        return b'$2b$12$...'

class SecureURLFetcher:
    """Fetching seguro de URLs previniendo SSRF"""
    
    DOMINIOS_PERMITIDOS = ['example.com', 'api.example.com']
    
    @classmethod
    def fetch_url(cls, url: str) -> bytes:
        """Fetch seguro de URL con validaciones contra SSRF"""
        import urllib.parse
        import urllib.request
        
        # Parsea URL
        parsed = urllib.parse.urlparse(url)
        
        # Validación de esquema
        if parsed.scheme not in ['http', 'https']:
            raise ValueError(f"Esquema no permitido: {parsed.scheme}")
        
        # Validación de dominio
        if not any(parsed.netloc.endswith(dom) for dom in cls.DOMINIOS_PERMITIDOS):
            raise ValueError(f"Dominio no permitido: {parsed.netloc}")
        
        # Validación contra IPs privadas
        try:
            # Resuelve hostname a IP
            import socket
            ip = socket.gethostbyname(parsed.hostname)
            ip_obj = ipaddress.ip_address(ip)
            
            # Bloquea IPs privadas, loopback, etc.
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                raise ValueError(f"IP no permitida: {ip}")
                
        except socket.gaierror:
            raise ValueError("No se pudo resolver hostname")
        
        # Realiza request con timeout
        try:
            request = urllib.request.Request(url)
            request.add_header('User-Agent', 'SecureApp/1.0')
            
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.read()
                
        except urllib.error.URLError as e:
            logger.error(f"Error fetching URL: {type(e).__name__}")
            raise

def division_segura(a: float, b: float) -> Optional[float]:
    """División con manejo de errores apropiado"""
    try:
        if b == 0:
            raise ValueError("División por cero")
        return a / b
    except (TypeError, ValueError) as e:
        logger.error(f"Error en división: {type(e).__name__}")
        return None

if __name__ == "__main__":
    # Ejemplo de uso seguro
    try:
        # Manejo seguro de archivos
        file_handler = SecureFileHandler('/var/data')
        contenido = file_handler.leer_archivo('datos.txt')
        
        # Autenticación segura
        auth = SecureAuthentication()
        
        # No acepta input directo sin validación
        print("Sistema de autenticación seguro inicializado")
        
    except Exception as e:
        logger.error(f"Error en la aplicación: {type(e).__name__}")
        # No expone detalles internos al usuario
        print("Ocurrió un error. Por favor contacte al administrador.")