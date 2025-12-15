import pandas as pd
import ast
from radon.complexity import cc_visit
from radon.metrics import mi_visit
from tqdm import tqdm

# RUTAS (Ajusta si es necesario)
INPUT_CSV = "data/cvefixes/raw/CVEFixes.csv"
OUTPUT_DATASET = "data/cvefixes/processed/dataset_features.csv"

# ---------------------------------------------------------
# 1. CLASE PARA MÉTRICAS AST (Reutilizada de tu script)
# ---------------------------------------------------------
class ASTMetrics(ast.NodeVisitor):
    def __init__(self):
        self.functions = 0
        self.classes = 0
        self.imports = 0
        self.nodes = 0
        self.control_structures = 0

    def visit_FunctionDef(self, node):
        self.functions += 1
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        self.classes += 1
        self.generic_visit(node)

    def visit_Import(self, node):
        self.imports += 1
    
    def visit_ImportFrom(self, node):
        self.imports += 1

    def generic_visit(self, node):
        self.nodes += 1
        # Estructuras de control comunes
        if isinstance(node, (ast.If, ast.For, ast.While, ast.Try, ast.With)):
            self.control_structures += 1
        super().generic_visit(node)

# ---------------------------------------------------------
# 2. FUNCIÓN DE EXTRACCIÓN (Adaptada para leer strings)
# ---------------------------------------------------------
def extract_metrics_from_text(code_str):
    # Métricas básicas de texto
    try:
        lines = code_str.splitlines()
        loc = len(lines)
        comments = sum(1 for line in lines if line.strip().startswith("#"))
    except:
        return None

    # Parsing AST
    try:
        tree = ast.parse(code_str)
    except SyntaxError:
        # Si el snippet está incompleto o tiene sintaxis inválida, lo ignoramos
        return None
    except Exception:
        return None

    # Métricas AST
    visitor = ASTMetrics()
    visitor.visit(tree)

    # Complejidad Ciclomática (Radon)
    try:
        complexity = sum([b.complexity for b in cc_visit(code_str)])
    except:
        complexity = 0

    # Índice de Mantenibilidad (Radon)
    try:
        mi = mi_visit(code_str, False)
    except:
        mi = 0

    return {
        "loc": loc,
        "comments": comments,
        "functions": visitor.functions,
        "classes": visitor.classes,
        "imports": visitor.imports,
        "ast_nodes": visitor.nodes,
        "control_structures": visitor.control_structures,
        "cyclomatic_complexity": complexity,
        "maintainability_index": mi
    }

# ---------------------------------------------------------
# 3. PROCESO PRINCIPAL (Filtro y Transformación)
# ---------------------------------------------------------
def main():
    print(f"--- FASE 2: MODIFY (Extracción de Características) ---")
    print(f"Cargando dataset desde {INPUT_CSV}...")
    
    # Cargamos todo el dataset
    df = pd.read_csv(INPUT_CSV)
    
    # FILTRO: Nos quedamos solo con Python
    print(f"Total filas iniciales: {len(df)}")
    df_py = df[df['language'] == 'py'].copy()
    print(f"Filas de Python encontradas: {len(df_py)}")

    results = []
    print("Extrayendo métricas (esto puede tardar unos minutos)...")

    # Iteramos sobre el DataFrame filtrado
    for _, row in tqdm(df_py.iterrows(), total=len(df_py)):
        code_content = row['code']
        safety_label = row['safety']
        
        # Extraemos métricas del código
        metrics = extract_metrics_from_text(code_content)
        
        if metrics:
            # Agregamos la etiqueta objetivo transformada (Binaria)
            # vulnerable = 1, safe = 0
            metrics['target'] = 1 if safety_label == 'vulnerable' else 0
            results.append(metrics)

    # Generamos el DataFrame final
    df_features = pd.DataFrame(results)
    
    # Guardamos
    import os
    os.makedirs(os.path.dirname(OUTPUT_DATASET), exist_ok=True)
    df_features.to_csv(OUTPUT_DATASET, index=False)

    print("\n=== FASE 2 COMPLETADA ===")
    print(f"Dataset de características guardado en: {OUTPUT_DATASET}")
    print(f"Muestras válidas procesadas: {len(df_features)}")
    print("Distribución de clases:")
    print(df_features['target'].value_counts())

if __name__ == "__main__":
    main()