import pandas as pd
import re
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix

# RUTAS
INPUT_CSV = "data/cvefixes/raw/CVEFixes.csv" 
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

# ---------------------------------------------------------
# 1. PREPROCESAMIENTO AVANZADO
# ---------------------------------------------------------
# Lista de "Stopwords" de Python para eliminar ruido
PYTHON_STOPWORDS = [
    'def', 'class', 'return', 'import', 'from', 'in', 'if', 'else', 'elif',
    'for', 'while', 'try', 'except', 'finally', 'with', 'as', 'pass', 
    'break', 'continue', 'lambda', 'global', 'nonlocal', 'assert', 'del', 
    'yield', 'raise', 'print', 'self', 'none', 'true', 'false', 'and', 'or', 'not',
    'is', 'package', 'public', 'private', 'protected', 'void', 'null' # Algunos de Java/C colados
]

def clean_code(text):
    if not isinstance(text, str): return ""
    text = re.sub(r'#.*', '', text) # Quitar comentarios
    text = text.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    # Solo alfanuméricos (La limpieza "agresiva" funcionó mejor para SVM)
    text = re.sub(r'[^A-Za-z0-9\s\(\)\[\]\{\}\.\_\=\-\"\']', '', text)
    return text

def train_final_model():
    print("--- FASE 3 (FINAL): MODELADO CON SVM + LIMPIEZA ---")
    
    # 1. Cargar Datos
    print("Cargando dataset...")
    df = pd.read_csv(INPUT_CSV)
    
    # Filtro estricto
    df = df[df['language'] == 'py'].copy()
    df = df.dropna(subset=['code'])
    
    # Crear Target
    df['target'] = df['safety'].apply(lambda x: 1 if x == 'vulnerable' else 0)
    
    print("Aplicando limpieza de código (eliminando comentarios y keywords)...")
    df['clean_code'] = df['code'].apply(clean_code)
    
    # Eliminar filas que quedaron vacías tras la limpieza
    df = df[df['clean_code'].str.strip().str.len() > 10]

    print(f"Total muestras limpias: {len(df)}")
    print(f"Distribución: {df['target'].value_counts().to_dict()}")

    # 2. Split
    X = df['clean_code']
    y = df['target']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    # 3. Pipeline: TF-IDF + SVM
    # Usamos LinearSVC porque es más rápido y efectivo para texto que SVC(kernel='rbf')
    # Usamos CalibratedClassifierCV para poder tener 'predict_proba' (necesario para AUC)
    
    svm = LinearSVC(class_weight='balanced', random_state=42, max_iter=2000)
    clf = CalibratedClassifierCV(svm) 

    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            max_features=5000, 
            ngram_range=(1, 3),      # Unigramas, Bigramas y Trigramas
            stop_words=PYTHON_STOPWORDS, # Quitamos 'def', 'import', etc.
            min_df=3                 # Ignorar palabras que aparecen en menos de 3 archivos
        )),
        ('clf', clf)
    ])

    print("\nEntrenando SVM (Support Vector Machine)...")
    pipeline.fit(X_train, y_train)

    # 4. Evaluación
    print("\nEvaluando...")
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    # Métricas
    print(classification_report(y_test, y_pred, target_names=["Seguro", "Vulnerable"]))
    
    auc = roc_auc_score(y_test, y_prob)
    print(f">>> ROC-AUC Score: {auc:.4f}")

    cm = confusion_matrix(y_test, y_pred)
    print(f">>> Matriz de Confusión: TN={cm[0][0]}, FP={cm[0][1]}, FN={cm[1][0]}, TP={cm[1][1]}")

    # 5. Interpretabilidad (Top Features para SVM Lineal)
    # Accedemos al modelo interno del CalibratedClassifierCV
    base_svm = pipeline.named_steps['clf'].estimator
    base_svm.fit(pipeline.named_steps['tfidf'].transform(X_train), y_train) # Re-fit rápido para sacar coeficientes
    
    feature_names = pipeline.named_steps['tfidf'].get_feature_names_out()
    coefs = base_svm.coef_.flatten()
    
    # DataFrame de importancia (Coeficientes positivos = Vulnerable, Negativos = Seguro)
    feat_df = pd.DataFrame({'Token': feature_names, 'Coeficiente': coefs})
    
    print("\n>>> Top 10 Tokens que indican VULNERABILIDAD (+):")
    print(feat_df.sort_values(by='Coeficiente', ascending=False).head(10))
    
    print("\n>>> Top 10 Tokens que indican SEGURIDAD (-):")
    print(feat_df.sort_values(by='Coeficiente', ascending=True).head(10))

    # Guardar
    joblib.dump(pipeline, os.path.join(MODEL_DIR, "best_model_svm.pkl"))
    print("\nModelo guardado en 'models/best_model_svm.pkl'")

if __name__ == "__main__":
    train_final_model()