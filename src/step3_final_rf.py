import pandas as pd
import re
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix

# RUTAS
INPUT_CSV = "data/cvefixes/raw/CVEFixes.csv" 
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

# ---------------------------------------------------------
# 1. LIMPIEZA MEJORADA (CRÍTICO: MANTENER SÍMBOLOS)
# ---------------------------------------------------------
# Stopwords: Quitamos palabras que confunden al modelo
PYTHON_STOPWORDS = [
    'def', 'class', 'return', 'import', 'from', 'in', 'if', 'else', 'elif',
    'for', 'while', 'try', 'except', 'finally', 'with', 'as', 'pass', 
    'print', 'self', 'none', 'true', 'false', 'is', 'not', 'and', 'or'
]

def clean_code(text):
    if not isinstance(text, str): return ""
    
    # 1. Eliminar comentarios
    text = re.sub(r'#.*', '', text)
    
    # 2. Normalizar espacios
    text = text.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    
    # 3. MANTENER SÍMBOLOS CLAVE (+, %, *, ,)
    # Antes borrábamos el +, por eso no detectaba concatenación insegura
    text = re.sub(r'[^A-Za-z0-9\s\(\)\[\]\{\}\.\_\=\-\"\'\+\%\*\,]', '', text)
    
    return text

def train_robust_model():
    print("--- FASE 3 (CORREGIDA): RANDOM FOREST + MEJOR LIMPIEZA ---")
    
    # 1. Cargar Datos
    print("Cargando dataset...")
    df = pd.read_csv(INPUT_CSV)
    df = df[df['language'] == 'py'].copy()
    df = df.dropna(subset=['code'])
    
    # Target
    df['target'] = df['safety'].apply(lambda x: 1 if x == 'vulnerable' else 0)
    
    print("Limpiando código (manteniendo operadores + y %)...")
    df['clean_code'] = df['code'].apply(clean_code)
    df = df[df['clean_code'].str.strip().str.len() > 10]

    print(f"Total muestras: {len(df)}")

    X = df['clean_code']
    y = df['target']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    # 2. Pipeline: TF-IDF + Random Forest
    # Random Forest es mejor detectando interacciones (ej: "execute" + "+")
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            max_features=3000,       # Reducimos ruido
            ngram_range=(1, 2),      # Capturar pares como "cursor.execute"
            stop_words=PYTHON_STOPWORDS,
            min_df=5                 # Ignorar palabras muy raras
        )),
        ('clf', RandomForestClassifier(
            n_estimators=300,        # Más árboles para estabilidad
            max_depth=20,            # Limitar profundidad para evitar memorizar
            class_weight='balanced', # Dar importancia a la clase minoritaria
            random_state=42,
            n_jobs=-1
        ))
    ])

    print("\nEntrenando Random Forest (esto puede tardar 1 min)...")
    pipeline.fit(X_train, y_train)

    # 3. Evaluación
    print("\nEvaluando...")
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    print(classification_report(y_test, y_pred, target_names=["Seguro", "Vulnerable"]))
    
    auc = roc_auc_score(y_test, y_prob)
    print(f">>> ROC-AUC Score: {auc:.4f}")

    # 4. Feature Importance (Para ver qué aprendió)
    feature_names = pipeline.named_steps['tfidf'].get_feature_names_out()
    importances = pipeline.named_steps['clf'].feature_importances_
    
    feat_df = pd.DataFrame({'Token': feature_names, 'Importancia': importances})
    print("\n>>> Top 10 Indicadores de Decisión:")
    print(feat_df.sort_values(by='Importancia', ascending=False).head(10))

    # Guardar
    joblib.dump(pipeline, os.path.join(MODEL_DIR, "best_model_svm.pkl")) # Sobreescribimos para usar el mismo verificador
    print("\nModelo actualizado guardado en 'models/best_model_svm.pkl'")

if __name__ == "__main__":
    train_robust_model()