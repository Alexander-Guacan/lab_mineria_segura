import pandas as pd
import numpy as np
import joblib
import json
from pathlib import Path
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, roc_auc_score, roc_curve
)
import matplotlib.pyplot as plt
import seaborn as sns

# ---------------------------------------------------------
# CONFIGURACIÓN
# ---------------------------------------------------------
DATASET = "data/meta/dataset_integrated.csv"
MODEL_OUTPUT = "data/meta/best_model.pkl"
SCALER_OUTPUT = "data/meta/scaler.pkl"
RESULTS_DIR = Path("data/results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# Features básicas (para compatibilidad con predict_risk)
BASIC_FEATURES = [
    "loc",
    "comments",
    "functions",
    "classes",
    "imports",
    "ast_nodes",
    "control_structures",
    "cyclomatic_complexity",
    "maintainability_index",
    "size_bytes"
]

print("=" * 70)
print("ENTRENAMIENTO DE MODELO INTEGRADO")
print("=" * 70)


# ---------------------------------------------------------
# 1. CARGAR Y PREPARAR DATOS
# ---------------------------------------------------------
print("\n Cargando dataset integrado...")
df = pd.read_csv(DATASET)

print(f" Dataset cargado: {len(df):,} registros")
print(f" Columnas: {len(df.columns)}")

# Verificar distribución
print(f"\n Distribución de labels:")
print(df['label'].value_counts())

# Separar features y target
X_columns = [col for col in df.columns if col not in ['label', 'data_source', 'original_safety']]
X = df[X_columns]
y = df['label']

print(f"\n Features seleccionadas: {len(X_columns)}")

# Verificar tipos de datos y filtrar solo columnas numéricas
numeric_columns = X.select_dtypes(include=[np.number]).columns.tolist()
non_numeric = [col for col in X_columns if col not in numeric_columns]

if non_numeric:
    print(f"\n Columnas no numéricas detectadas (serán excluidas de correlación): {non_numeric}")
    X = X[numeric_columns]
    X_columns = numeric_columns

# Mostrar features más importantes (correlación con label)
print(f"\n Top 10 features correlacionadas con vulnerabilidad:")
correlations = df[X_columns + ['label']].corr()['label'].abs().sort_values(ascending=False)
print(correlations.head(11)[1:])  # Excluir label mismo


# ---------------------------------------------------------
# 2. DIVISIÓN DE DATOS
# ---------------------------------------------------------
print(f"\n{'='*70}")
print("DIVISIÓN DE DATOS")
print(f"{'='*70}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

print(f"\n Datos divididos:")
print(f"   Train: {len(X_train):,} registros ({len(X_train)/len(X)*100:.1f}%)")
print(f"   Test:  {len(X_test):,} registros ({len(X_test)/len(X)*100:.1f}%)")

print(f"\n Distribución en train:")
print(y_train.value_counts())
print(f"\n Distribución en test:")
print(y_test.value_counts())


# ---------------------------------------------------------
# 3. ESCALADO DE FEATURES
# ---------------------------------------------------------
print(f"\n{'='*70}")
print("ESCALADO DE FEATURES")
print(f"{'='*70}")

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Guardar scaler para uso posterior
joblib.dump(scaler, SCALER_OUTPUT)
print(f" Scaler guardado en: {SCALER_OUTPUT}")


# ---------------------------------------------------------
# 4. ENTRENAMIENTO DE MODELOS MÚLTIPLES
# ---------------------------------------------------------
print(f"\n{'='*70}")
print("ENTRENAMIENTO DE MODELOS")
print(f"{'='*70}")

models = {}
results = {}

# Configuración de validación cruzada
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)


# --- Modelo 1: Random Forest ---
print(f"\n Entrenando Random Forest...")
rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)
rf.fit(X_train, y_train)
models['random_forest'] = rf

# Validación cruzada
cv_scores_rf = cross_val_score(rf, X_train, y_train, cv=cv, scoring='accuracy', n_jobs=-1)
print(f"   CV Accuracy: {cv_scores_rf.mean():.4f} (+/- {cv_scores_rf.std():.4f})")

# Evaluación en test
y_pred_rf = rf.predict(X_test)
y_proba_rf = rf.predict_proba(X_test)[:, 1]

results['random_forest'] = {
    'cv_accuracy': cv_scores_rf.mean(),
    'cv_std': cv_scores_rf.std(),
    'test_accuracy': accuracy_score(y_test, y_pred_rf),
    'test_precision': precision_score(y_test, y_pred_rf),
    'test_recall': recall_score(y_test, y_pred_rf),
    'test_f1': f1_score(y_test, y_pred_rf),
    'test_auc': roc_auc_score(y_test, y_proba_rf)
}

print(f"   Test Accuracy: {results['random_forest']['test_accuracy']:.4f}")
print(f"   Test AUC: {results['random_forest']['test_auc']:.4f}")


# --- Modelo 2: Gradient Boosting ---
print(f"\n Entrenando Gradient Boosting...")
gb = GradientBoostingClassifier(
    n_estimators=150,
    learning_rate=0.1,
    max_depth=8,
    random_state=42
)
gb.fit(X_train, y_train)
models['gradient_boosting'] = gb

cv_scores_gb = cross_val_score(gb, X_train, y_train, cv=cv, scoring='accuracy', n_jobs=-1)
print(f"   CV Accuracy: {cv_scores_gb.mean():.4f} (+/- {cv_scores_gb.std():.4f})")

y_pred_gb = gb.predict(X_test)
y_proba_gb = gb.predict_proba(X_test)[:, 1]

results['gradient_boosting'] = {
    'cv_accuracy': cv_scores_gb.mean(),
    'cv_std': cv_scores_gb.std(),
    'test_accuracy': accuracy_score(y_test, y_pred_gb),
    'test_precision': precision_score(y_test, y_pred_gb),
    'test_recall': recall_score(y_test, y_pred_gb),
    'test_f1': f1_score(y_test, y_pred_gb),
    'test_auc': roc_auc_score(y_test, y_proba_gb)
}

print(f"   Test Accuracy: {results['gradient_boosting']['test_accuracy']:.4f}")
print(f"   Test AUC: {results['gradient_boosting']['test_auc']:.4f}")


# --- Modelo 3: SVM ---
print(f"\n Entrenando SVM...")
svm = SVC(
    C=1.0,
    kernel='rbf',
    gamma='scale',
    probability=True,
    random_state=42
)
svm.fit(X_train_scaled, y_train)
models['svm'] = svm

cv_scores_svm = cross_val_score(svm, X_train_scaled, y_train, cv=cv, scoring='accuracy', n_jobs=-1)
print(f"   CV Accuracy: {cv_scores_svm.mean():.4f} (+/- {cv_scores_svm.std():.4f})")

y_pred_svm = svm.predict(X_test_scaled)
y_proba_svm = svm.predict_proba(X_test_scaled)[:, 1]

results['svm'] = {
    'cv_accuracy': cv_scores_svm.mean(),
    'cv_std': cv_scores_svm.std(),
    'test_accuracy': accuracy_score(y_test, y_pred_svm),
    'test_precision': precision_score(y_test, y_pred_svm),
    'test_recall': recall_score(y_test, y_pred_svm),
    'test_f1': f1_score(y_test, y_pred_svm),
    'test_auc': roc_auc_score(y_test, y_proba_svm)
}

print(f"   Test Accuracy: {results['svm']['test_accuracy']:.4f}")
print(f"   Test AUC: {results['svm']['test_auc']:.4f}")


# ---------------------------------------------------------
# 5. ENSEMBLE VOTING
# ---------------------------------------------------------
print(f"\n Creando Voting Ensemble...")

voting = VotingClassifier(
    estimators=[
        ('rf', rf),
        ('gb', gb),
    ],
    voting='soft',
    weights=[2, 1]  # Dar más peso a Random Forest
)
voting.fit(X_train, y_train)
models['voting_ensemble'] = voting

cv_scores_voting = cross_val_score(voting, X_train, y_train, cv=cv, scoring='accuracy', n_jobs=-1)
print(f"   CV Accuracy: {cv_scores_voting.mean():.4f} (+/- {cv_scores_voting.std():.4f})")

y_pred_voting = voting.predict(X_test)
y_proba_voting = voting.predict_proba(X_test)[:, 1]

results['voting_ensemble'] = {
    'cv_accuracy': cv_scores_voting.mean(),
    'cv_std': cv_scores_voting.std(),
    'test_accuracy': accuracy_score(y_test, y_pred_voting),
    'test_precision': precision_score(y_test, y_pred_voting),
    'test_recall': recall_score(y_test, y_pred_voting),
    'test_f1': f1_score(y_test, y_pred_voting),
    'test_auc': roc_auc_score(y_test, y_proba_voting)
}

print(f"   Test Accuracy: {results['voting_ensemble']['test_accuracy']:.4f}")
print(f"   Test AUC: {results['voting_ensemble']['test_auc']:.4f}")


# ---------------------------------------------------------
# 6. COMPARACIÓN Y SELECCIÓN DEL MEJOR MODELO
# ---------------------------------------------------------
print(f"\n{'='*70}")
print("COMPARACIÓN DE MODELOS")
print(f"{'='*70}")

# Tabla comparativa
print(f"\n{'Modelo':<20} {'CV Acc':<10} {'Test Acc':<10} {'Precision':<10} {'Recall':<10} {'F1':<10} {'AUC':<10}")
print("-" * 80)

for name, metrics in results.items():
    print(f"{name:<20} "
          f"{metrics['cv_accuracy']:.4f}     "
          f"{metrics['test_accuracy']:.4f}     "
          f"{metrics['test_precision']:.4f}     "
          f"{metrics['test_recall']:.4f}     "
          f"{metrics['test_f1']:.4f}     "
          f"{metrics['test_auc']:.4f}")

# Seleccionar mejor modelo (basado en CV accuracy)
best_model_name = max(results.items(), key=lambda x: x[1]['cv_accuracy'])[0]
best_model = models[best_model_name]
best_metrics = results[best_model_name]

print(f"\n{'='*70}")
print(f" MEJOR MODELO: {best_model_name.upper()}")
print(f"{'='*70}")
print(f"CV Accuracy: {best_metrics['cv_accuracy']:.4f} (+/- {best_metrics['cv_std']:.4f})")
print(f"Test Accuracy: {best_metrics['test_accuracy']:.4f}")
print(f"Test Precision: {best_metrics['test_precision']:.4f}")
print(f"Test Recall: {best_metrics['test_recall']:.4f}")
print(f"Test F1: {best_metrics['test_f1']:.4f}")
print(f"Test AUC: {best_metrics['test_auc']:.4f}")

# Verificar requisito del 82%
if best_metrics['cv_accuracy'] >= 0.82:
    print(f"\n REQUISITO CUMPLIDO: Accuracy >= 82%")
else:
    print(f"\n Accuracy por debajo del 82% requerido")


# ---------------------------------------------------------
# 7. REPORTE DETALLADO DEL MEJOR MODELO
# ---------------------------------------------------------
print(f"\n{'='*70}")
print("REPORTE DETALLADO")
print(f"{'='*70}")

# Predicciones del mejor modelo
if best_model_name == 'svm':
    y_pred_best = best_model.predict(X_test_scaled)
    y_proba_best = best_model.predict_proba(X_test_scaled)[:, 1]
else:
    y_pred_best = best_model.predict(X_test)
    y_proba_best = best_model.predict_proba(X_test)[:, 1]

print(f"\n Classification Report:")
print(classification_report(y_test, y_pred_best, target_names=['Safe', 'Vulnerable']))

print(f"\n Confusion Matrix:")
cm = confusion_matrix(y_test, y_pred_best)
print(cm)


# ---------------------------------------------------------
# 8. FEATURE IMPORTANCE (solo para modelos basados en árboles)
# ---------------------------------------------------------
if best_model_name in ['random_forest', 'gradient_boosting', 'voting_ensemble']:
    print(f"\n{'='*70}")
    print("IMPORTANCIA DE FEATURES")
    print(f"{'='*70}")
    
    if best_model_name == 'voting_ensemble':
        # Usar Random Forest del ensemble
        feature_importance = models['random_forest'].feature_importances_
    else:
        feature_importance = best_model.feature_importances_
    
    # Crear DataFrame de importancia
    feature_importance_df = pd.DataFrame({
        'feature': X_columns,
        'importance': feature_importance
    }).sort_values('importance', ascending=False)
    
    print(f"\n Top 15 features más importantes:")
    print(feature_importance_df.head(15).to_string(index=False))
    
    # Verificar si las features básicas están entre las importantes
    print(f"\n Importancia de features básicas (para predict_risk):")
    basic_importance = feature_importance_df[feature_importance_df['feature'].isin(BASIC_FEATURES)]
    print(basic_importance.to_string(index=False))


# ---------------------------------------------------------
# 9. GUARDAR MODELO
# ---------------------------------------------------------
print(f"\n{'='*70}")
print("GUARDANDO MODELO")
print(f"{'='*70}")

joblib.dump(best_model, MODEL_OUTPUT)
print(f" Modelo guardado en: {MODEL_OUTPUT}")

# Guardar metadata del modelo
model_metadata = {
    'model_type': best_model_name,
    'cv_accuracy': float(best_metrics['cv_accuracy']),
    'cv_std': float(best_metrics['cv_std']),
    'test_accuracy': float(best_metrics['test_accuracy']),
    'test_precision': float(best_metrics['test_precision']),
    'test_recall': float(best_metrics['test_recall']),
    'test_f1': float(best_metrics['test_f1']),
    'test_auc': float(best_metrics['test_auc']),
    'features_used': X_columns,
    'basic_features': BASIC_FEATURES,
    'total_training_samples': int(len(X_train)),
    'total_test_samples': int(len(X_test)),
    'meets_82_percent_requirement': bool(best_metrics['cv_accuracy'] >= 0.82)
}

metadata_path = RESULTS_DIR / "model_metadata.json"
with open(metadata_path, 'w') as f:
    json.dump(model_metadata, f, indent=2)

print(f" Metadata guardada en: {metadata_path}")

# Guardar todos los resultados - convertir valores NumPy a Python nativos
results_serializable = {}
for model_name, metrics in results.items():
    results_serializable[model_name] = {
        key: float(value) if isinstance(value, (np.floating, np.integer)) else value
        for key, value in metrics.items()
    }

all_results_path = RESULTS_DIR / "all_models_results.json"
with open(all_results_path, 'w') as f:
    json.dump(results_serializable, f, indent=2)

print(f" Resultados de todos los modelos guardados en: {all_results_path}")


# ---------------------------------------------------------
# 10. VISUALIZACIONES
# ---------------------------------------------------------
print(f"\n{'='*70}")
print("GENERANDO VISUALIZACIONES")
print(f"{'='*70}")

# Confusion Matrix heatmap
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
            xticklabels=['Safe', 'Vulnerable'],
            yticklabels=['Safe', 'Vulnerable'])
plt.title(f'Confusion Matrix - {best_model_name}')
plt.ylabel('True Label')
plt.xlabel('Predicted Label')
cm_path = RESULTS_DIR / 'confusion_matrix.png'
plt.savefig(cm_path, dpi=300, bbox_inches='tight')
plt.close()
print(f" Confusion matrix guardada en: {cm_path}")

# ROC Curve
plt.figure(figsize=(8, 6))
fpr, tpr, _ = roc_curve(y_test, y_proba_best)
plt.plot(fpr, tpr, label=f'{best_model_name} (AUC = {best_metrics["test_auc"]:.3f})')
plt.plot([0, 1], [0, 1], 'k--', label='Random')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('ROC Curve')
plt.legend()
plt.grid(True, alpha=0.3)
roc_path = RESULTS_DIR / 'roc_curve.png'
plt.savefig(roc_path, dpi=300, bbox_inches='tight')
plt.close()
print(f" ROC curve guardada en: {roc_path}")

# Feature Importance (si aplica)
if best_model_name in ['random_forest', 'gradient_boosting', 'voting_ensemble']:
    plt.figure(figsize=(10, 8))
    top_features = feature_importance_df.head(20)
    plt.barh(range(len(top_features)), top_features['importance'])
    plt.yticks(range(len(top_features)), top_features['feature'])
    plt.xlabel('Importance')
    plt.title(f'Top 20 Feature Importance - {best_model_name}')
    plt.gca().invert_yaxis()
    fi_path = RESULTS_DIR / 'feature_importance.png'
    plt.savefig(fi_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f" Feature importance guardada en: {fi_path}")


print(f"\n{'='*70}")
print(f" ENTRENAMIENTO COMPLETADO")
print(f"{'='*70}")
print(f"\nResultados:")
print(f"   Modelo: {best_model_name}")
print(f"   CV Accuracy: {best_metrics['cv_accuracy']:.4f}")
print(f"   Test Accuracy: {best_metrics['test_accuracy']:.4f}")
print(f"   Requisito 82%: {'CUMPLIDO ✓' if best_metrics['cv_accuracy'] >= 0.82 else 'NO CUMPLIDO ✗'}")
print(f"\nArchivos generados:")
print(f"  📁 {MODEL_OUTPUT}")
print(f"  📁 {SCALER_OUTPUT}")
print(f"  📁 {metadata_path}")
print(f"  📁 {cm_path}")
print(f"  📁 {roc_path}")