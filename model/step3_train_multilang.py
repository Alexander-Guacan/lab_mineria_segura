import pandas as pd
import re
import joblib
import os
import argparse
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.metrics import classification_report, roc_auc_score

# RUTAS
DATA_DIR = "data/partitioned"
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

# ---------------------------------------------------------
# 1. PERFILES DE RIESGO (CONFIGURACIÓN POR LENGUAJE)
# ---------------------------------------------------------
RISK_PROFILES = {
    "python": {
        "keywords": [
            'exec', 'eval', 'os.system', 'subprocess', 'shell=True', 
            'pickle.load', 'yaml.load', 'input', 'cursor.execute', 'md5', 'token'
        ],
        "stopwords": ['def', 'class', 'import', 'return', 'self']
    },
    "java": {
        "keywords": [
            'Runtime.exec', 'ProcessBuilder', 'Statement.execute', 'executeQuery', 
            'ObjectInputStream', 'readObject', 'MD5', 'SHA-1', 'password', 
            'get parameter', 'createStatement', 'jdbc'
        ],
        "stopwords": ['public', 'class', 'void', 'static', 'import', 'package', 'new']
    },
    "c_cpp": {
        "keywords": [
            'strcpy', 'strcat', 'sprintf', 'gets', 'system', 'popen', 'memcpy',
            'execl', 'execv', 'scanf', 'printf', 'malloc', 'free', 'buffer'
        ],
        "stopwords": ['int', 'void', 'char', 'include', 'return', 'struct', 'const']
    },
    "php": {
        "keywords": [
            'eval', 'exec', 'system', 'shell_exec', 'passthru', 'mysql_query', 
            'unserialize', 'md5', 'base64_decode', '$_GET', '$_POST'
        ],
        "stopwords": ['function', 'echo', 'return', 'class', 'public', 'private']
    },
    "js": {
        "keywords": [
            'eval', 'innerHTML', 'document.write', 'setTimeout', 'setInterval', 
            'exec', 'spawn', 'serialize', 'unserialize', 'child_process', 
            'dangerouslySetInnerHTML', '__proto__', 'prototype'
        ],
        "stopwords": [
            'var', 'const', 'let', 'function', 'return', 'class', 
            'import', 'export', 'default', 'console', 'log'
        ]
    }
}

# ---------------------------------------------------------
# 2. CLASES Y FUNCIONES DE SOPORTE
# ---------------------------------------------------------
class RiskKeywordCounter(BaseEstimator, TransformerMixin):
    def __init__(self, keywords=[]):
        self.keywords = keywords
        
    def fit(self, X, y=None): return self
    
    def transform(self, X):
        features = []
        for text in X:
            if not isinstance(text, str):
                features.append([0] * (len(self.keywords) + 1))
                continue
            # Contamos ocurrencias (case-insensitive para ser más robusto)
            text_lower = text.lower()
            row = [text_lower.count(k.lower()) for k in self.keywords]
            row.append(len(text) / 1000.0) 
            features.append(row)
        return np.array(features)

def clean_code(text):
    if not isinstance(text, str): return ""
    text = re.sub(r'#.*|//.*|/\*[\s\S]*?\*/', '', text) # Quitar comentarios Py/C/Java
    text = text.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    # Mantenemos símbolos universales (+, %, pointers *, etc)
    text = re.sub(r'[^A-Za-z0-9\s\(\)\[\]\{\}\.\_\=\-\"\'\+\%\*\,<>\&]', '', text)
    return text

# ---------------------------------------------------------
# 3. FUNCIÓN PRINCIPAL DE ENTRENAMIENTO
# ---------------------------------------------------------
def train_language_model(lang):
    print(f"\n{'='*60}")
    print(f"🚀 INICIANDO ENTRENAMIENTO PARA: {lang.upper()}")
    print(f"{'='*60}")
    
    # Validar soporte
    if lang not in RISK_PROFILES:
        print(f"❌ Error: Lenguaje '{lang}' no soportado en RISK_PROFILES.")
        return

    # --- INICIO DE LA INTEGRACIÓN DE DATASETS ---
    df_list = [] # Lista para acumular todos los CSVs que encontremos

    # 1. CARGAR DATASET BASE (El particionado o sintético)
    # Por defecto busca: data/partitioned/dataset_javascript.csv
    base_csv = os.path.join(DATA_DIR, f"dataset_{lang}.csv")
    if os.path.exists(base_csv):
        print(f"📂 Cargando Base ({lang}): {base_csv}")
        df_base = pd.read_csv(base_csv)
        df_list.append(df_base)
    else:
        print(f"⚠️ Advertencia: No se encontró el base {base_csv}")

    # 2. LÓGICA ESPECIAL PARA JAVASCRIPT (Aquí integramos tus nuevos archivos)
    if lang == "js":
        print("ℹ️ Detectado modo JavaScript: Buscando datasets extra...")

        # A) Dataset de Semgrep (Real)
        semgrep_csv = os.path.join(DATA_DIR, "dataset_js_real.csv")
        if os.path.exists(semgrep_csv):
            print(f"📂 Cargando Semgrep Real: {semgrep_csv}")
            df_semgrep = pd.read_csv(semgrep_csv)
            # Opcional: Multiplicar x2 para darle peso a los datos reales
            df_list.append(df_semgrep) 
        else:
            print(f"⚠️ No encontrado: {semgrep_csv}")

        # B) Dataset de CodeQL (Real)
        codeql_csv = os.path.join(DATA_DIR, "dataset_js_codeql.csv")
        if os.path.exists(codeql_csv):
            print(f"📂 Cargando CodeQL Real: {codeql_csv}")
            df_codeql = pd.read_csv(codeql_csv)
            df_list.append(df_codeql)
        else:
            print(f"⚠️ No encontrado: {codeql_csv}")

    # 3. FUSIÓN (MERGE)
    if not df_list:
        print(f"❌ Error Crítico: No hay NINGÚN dato para entrenar {lang}.")
        return

    # pandas.concat une todos los CSVs cargados en una sola tabla gigante
    print("🔗 Fusionando datasets...")
    df = pd.concat(df_list, ignore_index=True)
    
    # --- FIN DE LA INTEGRACIÓN ---

    # Limpieza básica (El resto del código sigue igual desde aquí)
    df = df.dropna(subset=['code'])
    df = df.drop_duplicates(subset=['code']) # Importante: eliminar códigos repetidos entre datasets
    df['clean_code'] = df['code'].apply(clean_code)
    
    print(f"📊 Muestras totales consolidadas: {len(df)}")
    print(f"   Vulnerables: {df['target'].sum()}")
    print(f"   Seguras: {len(df) - df['target'].sum()}")

    # 2. Configurar Pipelines con el Perfil del Lenguaje
    profile = RISK_PROFILES[lang]
    
    X = df['clean_code']
    y = df['target']
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print("⚙️ Configurando arquitectura del modelo...")
    pipeline = Pipeline([
        ('features', FeatureUnion([
            # Rama Texto (Contexto)
            ('text', Pipeline([
                ('tfidf', TfidfVectorizer(
                    max_features=5000, 
                    ngram_range=(1, 2), 
                    min_df=5,
                    stop_words=profile['stopwords'] # Stopwords específicas
                ))
            ])),
            # Rama Riesgo (Palabras clave específicas)
            ('risks', Pipeline([
                ('counter', RiskKeywordCounter(keywords=profile['keywords']))
            ]))
        ])),
        # Clasificador Robusto
        ('clf', RandomForestClassifier(
            n_estimators=300, 
            max_depth=30, 
            class_weight='balanced', 
            random_state=42, 
            n_jobs=-1
        ))
    ])

    # 3. Entrenamiento
    print("🏋️‍♂️ Entrenando (esto puede tardar dependiendo del tamaño)...")
    pipeline.fit(X_train, y_train)

    # 4. Evaluación
    print("\n📈 Evaluando modelo...")
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]
    
    print(classification_report(y_test, y_pred))
    auc = roc_auc_score(y_test, y_prob)
    print(f"⭐ ROC-AUC Score: {auc:.4f}")

    # 5. Guardar
    model_path = os.path.join(MODEL_DIR, f"best_model_{lang}.pkl")
    joblib.dump(pipeline, model_path)
    print(f"✅ Modelo guardado en: {model_path}")

if __name__ == "__main__":
    # Menú simple para elegir lenguaje
    print("Lenguajes disponibles: python, java, c_cpp, php, js, javascript")
    selected_lang = input("¿Qué lenguaje quieres entrenar hoy? > ").strip().lower()
    train_language_model(selected_lang)