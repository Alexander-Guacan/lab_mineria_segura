
# Procesador de datos con validación
import re
from typing import List, Dict, Optional
import hashlib
import secrets

class DataValidator:
    @staticmethod
    def validate_email(email: str) -> bool:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_phone(phone: str) -> bool:
        pattern = r'^\+?1?\d{9,15}$'
        return bool(re.match(pattern, phone))
    
    @staticmethod
    def sanitize_input(text: str) -> str:
        return re.sub(r'[<>"\'%;()&+]', '', text)

class SecureDataProcessor:
    def __init__(self):
        self.data_store = {}
        
    def process_user_data(self, user_data: Dict) -> Optional[Dict]:
        if not isinstance(user_data, dict):
            return None
            
        email = user_data.get('email', '')
        if not DataValidator.validate_email(email):
            return None
            
        processed = {
            'id': secrets.token_hex(16),
            'email': email,
            'created_at': self._get_timestamp()
        }
        
        return processed
    
    def _get_timestamp(self) -> str:
        from datetime import datetime
        return datetime.utcnow().isoformat()
    
    def hash_data(self, data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()

def process_records(records: List[Dict]) -> List[Dict]:
    processor = SecureDataProcessor()
    results = []
    
    for record in records:
        processed = processor.process_user_data(record)
        if processed:
            results.append(processed)
    
    return results
