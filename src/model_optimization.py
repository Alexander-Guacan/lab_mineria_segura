import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from scipy.stats import randint, uniform

DATASET = "data/meta/dataset_features.csv"
MODEL_OUTPUT = "data/meta/best_model.pkl"

print("Cargando dataset...")
df = pd.read_csv(DATASET)

FEATURES = [
    "loc", "comments", "functions", "classes", "imports",
    "ast_nodes", "control_structures", "cyclomatic_complexity",
    "maintainability_index", "size_bytes"
]

# ----------------------------------------------------
# CREAR risk_label (NO venía del Día 3)
# ----------------------------------------------------
df["risk_label"] = (
    (df["cyclomatic_complexity"] > 10) |
    (df["maintainability_index"] < 60) |
    (df["ast_nodes"] > 1000)
).astype(int)

print("Distribución de etiquetas:")
print(df["risk_label"].value_counts())

X = df[FEATURES]
y = df["risk_label"]

# ----------------------------------------------------
# Split + escalado
# ----------------------------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42
)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)


# ----------------------------------------------------
# Random Forest Optimization
# ----------------------------------------------------
rf = RandomForestClassifier()

param_dist_rf = {
    "n_estimators": randint(80, 200),
    "max_depth": randint(5, 20),
    "min_samples_split": randint(2, 15),
    "min_samples_leaf": randint(1, 10)
}

print("Optimizando Random Forest...")
search_rf = RandomizedSearchCV(
    rf, param_distributions=param_dist_rf,
    n_iter=20, cv=5, random_state=42, n_jobs=-1
)
search_rf.fit(X_train, y_train)
best_rf = search_rf.best_estimator_
print("Mejores parámetros RF:", search_rf.best_params_)


# ----------------------------------------------------
# SVM Optimization
# ----------------------------------------------------
svm = SVC(probability=True)

param_dist_svm = {
    "C": uniform(0.1, 10),
    "gamma": ["scale", "auto"],
    "kernel": ["rbf", "poly"]
}

print("Optimizando SVM...")
search_svm = RandomizedSearchCV(
    svm, param_distributions=param_dist_svm,
    n_iter=20, cv=5, random_state=42, n_jobs=-1
)
search_svm.fit(X_train_scaled, y_train)
best_svm = search_svm.best_estimator_
print("Mejores parámetros SVM:", search_svm.best_params_)


# ----------------------------------------------------
# Evaluación final
# ----------------------------------------------------
print("\n=== Evaluación Random Forest ===")
rf_pred = best_rf.predict(X_test)
print(classification_report(y_test, rf_pred))
print("AUC:", roc_auc_score(y_test, best_rf.predict_proba(X_test)[:,1]))

print("\n=== Evaluación SVM ===")
svm_pred = best_svm.predict(X_test_scaled)
print(classification_report(y_test, svm_pred))
print("AUC:", roc_auc_score(y_test, best_svm.predict_proba(X_test_scaled)[:,1]))


# ----------------------------------------------------
# Seleccionar mejor modelo
# ----------------------------------------------------
rf_auc = roc_auc_score(y_test, best_rf.predict_proba(X_test)[:,1])
svm_auc = roc_auc_score(y_test, best_svm.predict_proba(X_test_scaled)[:,1])

best_model = best_rf if rf_auc >= svm_auc else best_svm

print("\nModelo seleccionado:", type(best_model).__name__)
joblib.dump(best_model, MODEL_OUTPUT)

print(f"Modelo guardado en {MODEL_OUTPUT}")
