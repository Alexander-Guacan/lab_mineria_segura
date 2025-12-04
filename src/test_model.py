import os
import joblib
import numpy as np
import pandas as pd
from extract_features import extract_metrics_from_file
import json

MODEL_PATH = "data/meta/best_model.pkl"
SCALER_PATH = "data/meta/scaler.pkl"
METADATA_PATH = "data/results/model_metadata.json"

def test_model_on_file(filepath):
    """Prueba el modelo en un archivo específico"""
    
    print("=" * 70)
    print(f"PROBANDO MODELO EN: {filepath}")
    print("=" * 70)
    
    # Cargar modelo y scaler
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH) if os.path.exists(SCALER_PATH) else None
    
    # Cargar metadata
    with open(METADATA_PATH, 'r') as f:
        metadata = json.load(f)
    
    print(f"\n📊 Información del modelo:")
    print(f"   Tipo: {metadata['model_type']}")
    print(f"   Precisión (CV): {metadata['cv_accuracy']:.2%}")
    print(f"   Precisión (Test): {metadata['test_accuracy']:.2%}")
    print(f"   F1-Score: {metadata['test_f1']:.2%}")
    print(f"   AUC: {metadata['test_auc']:.2%}")
    
    # Extraer features del archivo
    print(f"\n🔍 Extrayendo características del archivo...")
    metrics = extract_metrics_from_file(filepath)
    
    if metrics is None:
        print("❌ Error al extraer métricas")
        return
    
    # Agregar size_bytes
    metrics["size_bytes"] = os.path.getsize(filepath)
    
    # Mostrar métricas extraídas
    print(f"\n📈 Características extraídas:")
    for key, value in metrics.items():
        print(f"   {key}: {value}")
    
    # Preparar datos para predicción
    features = metadata['basic_features']
    
    
    
    X = pd.DataFrame(
        [[metrics.get(feat, 0) for feat in features]], 
        columns=features
    )
    
    # Aplicar scaler
    if scaler:
        X_scaled = scaler.transform(X)
        X = pd.DataFrame(X_scaled, columns=features)
    
    # Predecir
    prediction = model.predict(X)[0]
    probability = model.predict_proba(X)[0]
    
    print(f"\n{'='*70}")
    print("RESULTADO DE LA PREDICCIÓN")
    print(f"{'='*70}")
    print(f"\n🎯 Clasificación: {'⚠️ VULNERABLE' if prediction == 1 else '✅ SEGURO'}")
    print(f"📊 Probabilidad de ser SEGURO: {probability[0]:.2%}")
    print(f"📊 Probabilidad de ser VULNERABLE: {probability[1]:.2%}")
    
    # Interpretación
    print(f"\n💡 Interpretación:")
    if probability[1] >= 0.8:
        print("   🔴 ALTO RIESGO - Revisar urgentemente")
    elif probability[1] >= 0.5:
        print("   🟡 RIESGO MEDIO - Se recomienda revisión")
    else:
        print("   🟢 BAJO RIESGO - Código relativamente seguro")
    
    return {
        "prediction": int(prediction),
        "probability_safe": float(probability[0]),
        "probability_vulnerable": float(probability[1]),
        "metrics": metrics
    }


def test_multiple_files(filepaths):
    """Prueba el modelo en múltiples archivos"""
    results = []
    
    for filepath in filepaths:
        if os.path.exists(filepath):
            result = test_model_on_file(filepath)
            if result:
                result['filepath'] = filepath
                results.append(result)
        else:
            print(f"❌ Archivo no encontrado: {filepath}")
    
    # Resumen
    print(f"\n{'='*70}")
    print("RESUMEN DE RESULTADOS")
    print(f"{'='*70}")
    
    for result in results:
        status = "⚠️ VULNERABLE" if result['prediction'] == 1 else "✅ SEGURO"
        prob = result['probability_vulnerable']
        print(f"{status} | {prob:.1%} | {result['filepath']}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Uso: python test_model.py <archivo.py> [archivo2.py ...]")
        print("\nEjemplo:")
        print("  python test_model.py ..\\tests\\vulnerable_code.py")
        print("  python test_model.py ..\\tests\\vulnerable_code.py ..\\tests\\flask_project\\app.py")
    else:
        test_multiple_files(sys.argv[1:])