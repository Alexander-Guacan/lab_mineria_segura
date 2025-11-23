import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.cluster import KMeans
from sklearn.svm import SVC
from tqdm import tqdm

DATASET = "data/meta/dataset_features.csv"


# ---------------------------------------------------------
#   1. Cargar y limpiar dataset
# ---------------------------------------------------------
print("Cargando dataset...")
df = pd.read_csv(DATASET)

# Eliminar filas con NaN (si hay)
df = df.dropna()

# Características que vamos a usar
FEATURES = [
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

X = df[FEATURES]


# ---------------------------------------------------------
#   2. Crear etiqueta de riesgo (supervisado)
# ---------------------------------------------------------
df["risk_label"] = (
    (df["cyclomatic_complexity"] > 10) |
    (df["maintainability_index"] < 60) |
    (df["ast_nodes"] > 1000)
).astype(int)

y = df["risk_label"]

print("Distribución de etiquetas:")
print(df["risk_label"].value_counts())


# ---------------------------------------------------------
#   3. Dividir dataset
# ---------------------------------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42
)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)


# ---------------------------------------------------------
#   4. Modelos Supervisados
# ---------------------------------------------------------
def evaluate_model(name, model, X_test, y_test):
    preds = model.predict(X_test)
    print(f"\n=== Resultados: {name} ===")
    print("Accuracy:", accuracy_score(y_test, preds))
    print("Precision:", precision_score(y_test, preds))
    print("Recall:", recall_score(y_test, preds))
    print("F1:", f1_score(y_test, preds))


# --- Decision Tree ---
tree = DecisionTreeClassifier(max_depth=10)
tree.fit(X_train, y_train)
evaluate_model("Decision Tree", tree, X_test, y_test)

# --- Random Forest ---
rf = RandomForestClassifier(n_estimators=120, max_depth=12)
rf.fit(X_train, y_train)
evaluate_model("Random Forest", rf, X_test, y_test)

# --- SVM ---
svm = SVC(kernel="rbf")
svm.fit(X_train_scaled, y_train)
evaluate_model("SVM", svm, X_test_scaled, y_test)


# ---------------------------------------------------------
#   5. Modelos No Supervisados
# ---------------------------------------------------------

# --- K-Means ---
print("\n=== K-Means ===")
kmeans = KMeans(n_clusters=2, random_state=42)
kmeans.fit(X_train_scaled)
print("Clusters generados:", np.unique(kmeans.labels_))

# --- Isolation Forest ---
print("\n=== Isolation Forest ===")
iso = IsolationForest(contamination=0.1)
iso.fit(X_train)
anom_preds = iso.predict(X_train)
print("Anomalías detectadas:", list(anom_preds).count(-1))


print("\n=== DÍA 4 COMPLETADO ===")
