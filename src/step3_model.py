import pandas as pd
import numpy as np
import joblib
import os
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.svm import SVC
from sklearn.cluster import KMeans

# CONFIGURACIÓN
DATASET_PATH = "data/cvefixes/processed/dataset_features.csv"
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

def train_and_evaluate():
    print("--- FASE 3: MODEL (Entrenamiento y Evaluación Preliminar) ---")
    
    # 1. Cargar datos
    if not os.path.exists(DATASET_PATH):
        print("Error: No se encuentra el dataset procesado. Ejecuta la Fase 2 primero.")
        return

    df = pd.read_csv(DATASET_PATH)
    
    # Características (Features) y Etiqueta (Target)
    # Excluimos columnas que no son numéricas o no aportan al modelo matemático directo
    feature_cols = [
        "loc", "comments", "functions", "classes", "imports", 
        "ast_nodes", "control_structures", "cyclomatic_complexity", 
        "maintainability_index"
    ]
    
    X = df[feature_cols]
    y = df["target"]

    print(f"Dataset cargado: {X.shape[0]} muestras, {X.shape[1]} características.")

    # 2. División Train/Test (70% entreno, 30% prueba)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    # 3. Escalado de datos (Crucial para SVM y K-Means)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Guardamos el escalador para usarlo en el futuro pipeline
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))

    # ==========================================
    # MODELOS SUPERVISADOS [cite: 28]
    # ==========================================
    
    models = {
        "Decision Tree": DecisionTreeClassifier(max_depth=10, random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
        "SVM": SVC(kernel="rbf", probability=True, random_state=42)
    }

    best_model = None
    best_f1 = 0

    print("\nResultados Modelos Supervisados:")
    print(f"{'Modelo':<20} | {'Acc':<8} | {'Prec':<8} | {'Recall':<8} | {'F1':<8}")
    print("-" * 65)

    for name, model in models.items():
        # Usamos datos escalados para SVM, datos normales para árboles (aunque escalados no les afecta mal)
        X_t = X_train_scaled if name == "SVM" else X_train
        X_v = X_test_scaled if name == "SVM" else X_test
        
        # Entrenamiento
        model.fit(X_t, y_train)
        preds = model.predict(X_v)
        
        # Métricas [cite: 59]
        acc = accuracy_score(y_test, preds)
        prec = precision_score(y_test, preds)
        rec = recall_score(y_test, preds)
        f1 = f1_score(y_test, preds)
        
        print(f"{name:<20} | {acc:.4f}   | {prec:.4f}   | {rec:.4f}   | {f1:.4f}")

        # Guardamos el mejor modelo basado en F1-Score
        if f1 > best_f1:
            best_f1 = f1
            best_model = model
            best_name = name

    # Guardar el mejor modelo
    if best_model:
        joblib.dump(best_model, os.path.join(MODEL_DIR, "best_model.pkl"))
        print(f"\n[INFO] Mejor modelo guardado: {best_name} (F1: {best_f1:.4f}) en '{MODEL_DIR}/best_model.pkl'")

    # ==========================================
    # MODELOS NO SUPERVISADOS [cite: 33, 39]
    # ==========================================
    print("\n--- Análisis No Supervisado (Exploratorio) ---")
    
    # K-Means 
    kmeans = KMeans(n_clusters=2, random_state=42, n_init=10)
    kmeans.fit(X_train_scaled)
    # Evaluamos si los clusters coinciden con las etiquetas reales (pureza simple)
    # Nota: K-means puede asignar 0 a vulnerable y 1 a seguro o viceversa.
    print(f"K-Means (Clustering): Clusters generados {np.unique(kmeans.labels_)}")
    
    # Isolation Forest (Detección de Anomalías) 
    iso = IsolationForest(contamination=0.1, random_state=42)
    iso.fit(X_train)
    anomalias = iso.predict(X_test)
    # Isolation Forest devuelve -1 para anomalía, 1 para normal
    n_anomalias = list(anomalias).count(-1)
    print(f"Isolation Forest: Detectadas {n_anomalias} anomalías en el set de prueba.")

    print("\n=== FASE 3 COMPLETADA ===")

if __name__ == "__main__":
    train_and_evaluate()