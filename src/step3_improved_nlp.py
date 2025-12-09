import pandas as pd
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix

# RUTAS
# Usamos el CSV original filtrado o el que ya tenías, 
# pero necesitamos la columna de TEXTO original ('code'). 
# El processed de la fase 2 NO guardó el texto, así que volvamos al raw o al intermedio.
# Para asegurar que funcione, cargaremos el raw y filtraremos igual que en fase 2.
INPUT_CSV = "data/cvefixes/raw/CVEFixes.csv" 
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

def train_improved_model():
    print("--- FASE 3 (MEJORADA): MODELADO CON NLP (TF-IDF) ---")
    
    # 1. Cargar Datos
    print("Cargando dataset...")
    df = pd.read_csv(INPUT_CSV)
    
    # Filtro Python (Igual que antes)
    df = df[df['language'] == 'py'].copy()
    
    # Limpieza básica: Eliminar filas vacías en 'code'
    df = df.dropna(subset=['code'])
    
    # Crear Target
    df['target'] = df['safety'].apply(lambda x: 1 if x == 'vulnerable' else 0)
    
    print(f"Total muestras Python: {len(df)}")
    print(f"Distribución: {df['target'].value_counts().to_dict()}")

    # 2. Definir X e y
    # X ahora es EL TEXTO DEL CÓDIGO, no números.
    X = df['code']
    y = df['target']

    # 3. Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    # 4. Crear Pipeline (Vectorización + Modelo)
    # TfidfVectorizer: Convierte código en una matriz gigante de palabras clave
    # max_features=3000: Nos quedamos con las 3000 palabras más importantes del código
    # ngram_range=(1, 2): Mira palabras sueltas ("exec") y pares ("cursor.execute")
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(max_features=3000, ngram_range=(1, 2))),
        ('clf', RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1))
    ])

    print("\nEntrenando modelo NLP (esto puede tardar un poco)...")
    pipeline.fit(X_train, y_train)

    # 5. Evaluación
    print("\nEvaluando...")
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    # Métricas
    print(classification_report(y_test, y_pred, target_names=["Seguro", "Vulnerable"]))
    
    auc = roc_auc_score(y_test, y_prob)
    print(f">>> ROC-AUC Score: {auc:.4f}")

    cm = confusion_matrix(y_test, y_pred)
    print(f">>> Matriz de Confusión: TN={cm[0][0]}, FP={cm[0][1]}, FN={cm[1][0]}, TP={cm[1][1]}")

    # 6. Ver qué palabras aprendió el modelo (Interpretabilidad)
    # Extraemos los nombres de las features del vectorizador y la importancia del Random Forest
    feature_names = pipeline.named_steps['tfidf'].get_feature_names_out()
    importances = pipeline.named_steps['clf'].feature_importances_
    
    # Creamos un DataFrame para ver el Top 20
    feat_df = pd.DataFrame({'Token': feature_names, 'Importancia': importances})
    feat_df = feat_df.sort_values(by='Importancia', ascending=False).head(20)
    
    print("\n>>> Top 20 'Tokens' (Palabras/Código) que indican riesgo/seguridad:")
    print(feat_df)

    # Guardar
    joblib.dump(pipeline, os.path.join(MODEL_DIR, "best_model_nlp.pkl"))
    print("\nModelo guardado en 'models/best_model_nlp.pkl'")

if __name__ == "__main__":
    train_improved_model()