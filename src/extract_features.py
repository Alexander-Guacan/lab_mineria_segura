import os
import ast
import pandas as pd
from radon.complexity import cc_visit
from radon.metrics import mi_visit, h_visit
from tqdm import tqdm

RAW_DATASET = "data/meta/dataset_raw.csv"
OUTPUT_DATASET = "data/meta/dataset_features.csv"


# ---------------------------------------------------------
# MÉTRICAS BASADAS EN AST
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

        # estructuras de control
        if isinstance(node, (ast.If, ast.For, ast.While, ast.Try, ast.With)):
            self.control_structures += 1

        super().generic_visit(node)


# ---------------------------------------------------------
# EXTRACCIÓN DE MÉTRICAS POR ARCHIVO
# ---------------------------------------------------------
def extract_metrics_from_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            code = f.read()
    except:
        return None

    lines = code.splitlines()
    loc = len(lines)
    comments = sum(1 for line in lines if line.strip().startswith("#"))

    try:
        tree = ast.parse(code)
    except Exception:
        return None

    # AST metrics
    visitor = ASTMetrics()
    visitor.visit(tree)

    # Complejidad ciclomática total
    try:
        complexity = sum([b.complexity for b in cc_visit(code)])
    except:
        complexity = 0

    # Maintainability index (radon)
    try:
        mi = mi_visit(code, False)
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
# PROCESO PRINCIPAL
# ---------------------------------------------------------
def main():
    print("Cargando dataset raw...")
    df = pd.read_csv(RAW_DATASET)

    results = []
    print("Extrayendo métricas de archivos...")

    for _, row in tqdm(df.iterrows(), total=len(df)):
        metrics = extract_metrics_from_file(row["file_path"])

        if metrics:
            metrics["repo"] = row["repo"]
            metrics["file_path"] = row["file_path"]
            metrics["size_bytes"] = row["size_bytes"]
            results.append(metrics)

    print("Generando dataset final...")
    df_out = pd.DataFrame(results)
    df_out.to_csv(OUTPUT_DATASET, index=False)

    print(f"\n=== COMPLETADO ===")
    print(f"Dataset generado en: {OUTPUT_DATASET}")
    print(f"Total archivos válidos analizados: {len(df_out)}")


if __name__ == "__main__":
    main()
