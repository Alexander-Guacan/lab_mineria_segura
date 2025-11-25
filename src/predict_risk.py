import ast
import joblib
import json
import sys
from pathlib import Path
from radon.metrics import mi_visit
from radon.complexity import cc_visit

MODEL_PATH = "data/meta/best_model.pkl"

def extract_features(file_path):
    try:
        code = Path(file_path).read_text(encoding="utf-8")
    except:
        return None

    try:
        tree = ast.parse(code)
    except:
        return None

    loc = len(code.splitlines())
    comments = sum(1 for line in code.splitlines() if line.strip().startswith("#"))
    functions = sum(isinstance(n, ast.FunctionDef) for n in ast.walk(tree))
    classes = sum(isinstance(n, ast.ClassDef) for n in ast.walk(tree))
    imports = sum(isinstance(n, (ast.Import, ast.ImportFrom)) for n in ast.walk(tree))
    ast_nodes = sum(1 for _ in ast.walk(tree))
    control_structures = sum(isinstance(n, (ast.If, ast.For, ast.While, ast.Try)) for n in ast.walk(tree))
    cc = sum(block.complexity for block in cc_visit(code))
    mi = mi_visit(code, True)
    size_bytes = len(code.encode("utf-8"))

    return {
        "loc": loc,
        "comments": comments,
        "functions": functions,
        "classes": classes,
        "imports": imports,
        "ast_nodes": ast_nodes,
        "control_structures": control_structures,
        "cyclomatic_complexity": cc,
        "maintainability_index": mi,
        "size_bytes": size_bytes
    }


if __name__ == "__main__":
    file_path = sys.argv[1]
    features = extract_features(file_path)

    if features is None:
        print(json.dumps({"error": "No se pudo analizar el archivo"}))
        sys.exit(1)

    model = joblib.load(MODEL_PATH)

    X = [list(features.values())]
    pred = model.predict(X)[0]

    print(json.dumps({
        "file": file_path,
        "prediction": int(pred),
        "risk": "ALTO" if pred == 1 else "BAJO",
        "features": features
    }))
