import pandas as pd
import joblib
import os
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, roc_auc_score, roc_curve, classification_report
from sklearn.model_selection import train_test_split

# CONFIGURACIÓN
DATASET_PATH = "data/cvefixes/processed/dataset_features.csv"
MODEL_PATH = "models/best_model.pkl"
SCALER_PATH = "models/scaler.pkl"

def assess_model():
    print("--- FASE 4: ASSESS (Evaluación Detallada) ---")

    # 1. Cargar recursos
    if not os.path.exists(MODEL_PATH) or not os.path.exists(DATASET_PATH):
        print("Error: Faltan archivos de la Fase 3.")
        return

    model = joblib.load(MODEL_PATH)
    try:
        scaler = joblib.load(SCALER_PATH)
    except:
        scaler = None
        
    df = pd.read_csv(DATASET_PATH)
    
    # Preparar datos (Igual que en Fase 3)
    feature_cols = [
        "loc", "comments", "functions", "classes", "imports", 
        "ast_nodes", "control_structures", "cyclomatic_complexity", 
        "maintainability_index"
    ]
    
    X = df[feature_cols]
    y = df["target"]

    # Usamos el mismo random_state para asegurar que el test set sea el mismo
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    
    # Si es SVM o K-means usamos el scaler, pero el árbol (best_model) usualmente no lo requiere.
    # Aún así, por consistencia, aplicamos si el modelo fue entrenado con ello.
    # Nota: En el paso 3, el árbol se entrenó con X_train normal (no scaled).
    # Asumimos que el "best_model" fue el Decision Tree según tu output.
    
    print(f"Evaluando modelo: {type(model).__name__}")
    
    # 2. Predicciones
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1] # Probabilidad para clase 1 (Vulnerable)

    # 3. Matriz de Confusión
    cm = confusion_matrix(y_test, y_pred)
    
    print("\n>>> Matriz de Confusión:")
    print(f"Verdaderos Negativos (Seguro predicho Seguro): {cm[0][0]}")
    print(f"Falsos Positivos (Seguro predicho Vulnerable): {cm[0][1]}")
    print(f"Falsos Negativos (Vulnerable predicho Seguro): {cm[1][0]}")
    print(f"Verdaderos Positivos (Vulnerable predicho Vulnerable): {cm[1][1]}")

    # 4. Reporte Completo
    print("\n>>> Reporte de Clasificación:")
    print(classification_report(y_test, y_pred, target_names=["Seguro", "Vulnerable"]))

    # 5. ROC - AUC (Requerido por el PDF)
    auc = roc_auc_score(y_test, y_prob)
    print(f">>> Área bajo la curva (ROC-AUC): {auc:.4f}")
    print("(0.5 es azar, 1.0 es perfecto, <0.5 el modelo predice al revés)")

    # 6. Importancia de Características (Feature Importance)
    if hasattr(model, "feature_importances_"):
        print("\n>>> Importancia de las Características (¿En qué se fijó el modelo?):")
        importances = model.feature_importances_
        feature_imp = pd.DataFrame({'Feature': feature_cols, 'Importance': importances})
        feature_imp = feature_imp.sort_values(by='Importance', ascending=False)
        print(feature_imp)
    else:
        print("\nEl modelo seleccionado no soporta ranking de características directo.")

    print("\n=== FASE 4 COMPLETADA ===")

if __name__ == "__main__":
    assess_model()