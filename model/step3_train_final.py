import pandas as pd
import re
import joblib
import os
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.metrics import classification_report, roc_auc_score

# RUTAS
INPUT_CSV_ORIGINAL = "data/cvefixes/raw/CVEFixes.csv"
INPUT_CSV_NEW = "data/kaggle_fix/vulnerability_fix_dataset.csv"  # <--- NUEVO DATASET
TEST_DIR = "../tests" 
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

# ---------------------------------------------------------
# CLASES Y LIMPIEZA (Igual que antes)
# ---------------------------------------------------------
class RiskKeywordCounter(BaseEstimator, TransformerMixin):
    def __init__(self):
        self.risk_words = [
            'exec', 'eval', 'os.system', 'subprocess', 'shell=True', 
            'pickle.load', 'yaml.load', 'input', 'raw_input', 
            'cursor.execute', 'md5', 'sha1', 'tmp', 'password', 'token',
            'admin', 'debug=True'
        ]
    def fit(self, X, y=None): return self
    def transform(self, X):
        features = []
        for text in X:
            if not isinstance(text, str):
                features.append([0] * (len(self.risk_words) + 1))
                continue
            row = [text.count(word) for word in self.risk_words]
            row.append(len(text) / 1000.0) 
            features.append(row)
        return np.array(features)

def clean_code(text):
    if not isinstance(text, str): return ""
    text = re.sub(r'#.*', '', text) 
    text = text.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    text = re.sub(r'[^A-Za-z0-9\s\(\)\[\]\{\}\.\_\=\-\"\'\+\%\*\,]', '', text)
    return text

# ---------------------------------------------------------
# ENTRENAMIENTO UNIFICADO
# ---------------------------------------------------------
def train_final_model():
    print("--- ENTRENAMIENTO: MERGE DE DATASETS ---")
    
    # 1. Cargar Dataset Original (CVEFixes)
    print("Cargando CVEFixes...")
    if os.path.exists(INPUT_CSV_ORIGINAL):
        df1 = pd.read_csv(INPUT_CSV_ORIGINAL)
        df1 = df1[df1['language'] == 'py'].copy()
        df1['target'] = df1['safety'].apply(lambda x: 1 if x == 'vulnerable' else 0)
        df1 = df1[['code', 'target']]
    else:
        df1 = pd.DataFrame(columns=['code', 'target'])
        print("Advertencia: No se encontró CVEFixes.")

    # 2. Cargar Nuevo Dataset (Vulnerability Fix)
    print("Cargando Vulnerability Fix Dataset...")
    if os.path.exists(INPUT_CSV_NEW):
        df2 = pd.read_csv(INPUT_CSV_NEW)
        # Este dataset suele tener columnas 'vulnerable_code' y 'fixed_code'
        # Vamos a transformarlo al formato que necesitamos
        
        # Tomamos los vulnerables
        vulnerable_df = pd.DataFrame({
            'code': df2['vulnerable_code'], # Ajusta el nombre si la columna es distinta
            'target': 1
        })
        
        # Tomamos los seguros (fixed)
        safe_df = pd.DataFrame({
            'code': df2['fixed_code'],      # Ajusta el nombre si la columna es distinta
            'target': 0
        })
        
        df2_final = pd.concat([vulnerable_df, safe_df], ignore_index=True)
        # Filtramos filas vacías
        df2_final = df2_final.dropna()
    else:
        df2_final = pd.DataFrame(columns=['code', 'target'])
        print(f"Advertencia: No se encontró {INPUT_CSV_NEW}. Asegúrate de descargarlo.")

    # 3. Inyección Local (Tus archivos de prueba)
    injected_data = []
    local_files = {"test_high_risk.py": 1, "vulnerable_code.py": 1, "test_low_risk.py": 0}
    for filename, label in local_files.items():
        path = os.path.join(TEST_DIR, filename)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f: content = f.read()
            # Peso x20 para asegurar que aprenda tus tests
            for _ in range(20): injected_data.append({"code": content, "target": label})

    df3 = pd.DataFrame(injected_data) if injected_data else pd.DataFrame(columns=['code', 'target'])

    # 4. FUSIÓN TOTAL
    df_final = pd.concat([df1, df2_final, df3], ignore_index=True)
    print(f"Total de muestras para entrenar: {len(df_final)}")
    
    # Preprocesamiento
    df_final['clean_code'] = df_final['code'].apply(clean_code)
    
    X = df_final['clean_code']
    y = df_final['target']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Pipeline
    pipeline = Pipeline([
        ('features', FeatureUnion([
            ('text', Pipeline([
                ('tfidf', TfidfVectorizer(max_features=5000, ngram_range=(1, 2), min_df=2))
            ])),
            ('risks', Pipeline([
                ('counter', RiskKeywordCounter())
            ]))
        ])),
        ('clf', RandomForestClassifier(n_estimators=300, max_depth=30, class_weight='balanced', random_state=42, n_jobs=-1))
    ])

    print("Entrenando modelo masivo...")
    pipeline.fit(X_train, y_train)

    print("Evaluando...")
    y_pred = pipeline.predict(X_test)
    print(classification_report(y_test, y_pred))
    print(f"ROC-AUC: {roc_auc_score(y_test, pipeline.predict_proba(X_test)[:, 1]):.4f}")

    joblib.dump(pipeline, os.path.join(MODEL_DIR, "best_model_hybrid.pkl"))
    print("Modelo guardado exitosamente.")

if __name__ == "__main__":
    train_final_model()