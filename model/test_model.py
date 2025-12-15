"""
Script para probar el modelo con los archivos de prueba
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np
import json
from pathlib import Path
from extract_features import extract_metrics_from_file

# Rutas de archivos del modelo
#MODEL_PATH = "data/meta/best_model_corrected.pkl"
MODEL_PATH = "models/best_model_svm.pkl"
#SCALER_PATH = "data/meta/scaler_corrected.pkl"
SCALER_PATH = "models/scaler.pkl"
METADATA_PATH = "data/results/model_metadata.json"

# Archivos de prueba
test_files = [
    ("..\\tests\\test_high_risk.py", "ALTO"),
    ("..\\tests\\test_low_risk.py", "BAJO"),
    ("..\\tests\\vulnerable_code.py", "ALTO")
]

def predict_risk_detailed(filepath):
    """
    Predice el riesgo de un archivo Python con detalles completos
    
    Args:
        filepath: Ruta al archivo .py
        
    Returns:
        dict: Diccionario con detalles de la predicción
    """
    
    # Verificar que existe el modelo
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"No se encontró el modelo en {MODEL_PATH}")
    
    # Cargar modelo
    model = joblib.load(MODEL_PATH)
    
    # Cargar scaler si existe
    scaler = None
    if os.path.exists(SCALER_PATH):
        scaler = joblib.load(SCALER_PATH)
    
    # Cargar metadata si existe
    features_required = []
    model_type = "unknown"
    
    if os.path.exists(METADATA_PATH):
        with open(METADATA_PATH, 'r') as f:
            metadata = json.load(f)
            features_required = metadata.get('basic_features', [])
            model_type = metadata.get('model_type', 'unknown')
    
    # Extraer métricas del archivo
    metrics = extract_metrics_from_file(filepath)
    
    if metrics is None:
        return {
            "error": "Failed to extract metrics",
            "risk_probability": 0.0
        }
    
    # CORRECCIÓN: Solo agregar size_bytes si está en las features requeridas
    if "size_bytes" in features_required and "size_bytes" not in metrics:
        metrics["size_bytes"] = os.path.getsize(filepath)
    
    # Construir DataFrame SOLO con las features requeridas (en el orden correcto)
    X = pd.DataFrame(
        [[metrics.get(feat, 0) for feat in features_required]], 
        columns=features_required
    )
    
    # Aplicar scaler si existe
    if scaler is not None:
        X_scaled = scaler.transform(X)
        X = pd.DataFrame(X_scaled, columns=features_required)
    
    # Predecir
    prediction = model.predict(X)[0]
    probability = model.predict_proba(X)[0]
    
    # Determinar nivel de riesgo
    risk_prob = float(probability[1])
    if risk_prob >= 0.7:
        risk_level = "ALTO"
    elif risk_prob >= 0.3:
        risk_level = "MEDIO"
    else:
        risk_level = "BAJO"
    
    return {
        "filepath": filepath,
        "risk_probability": risk_prob,
        "probability_safe": float(probability[0]),
        "probability_vulnerable": float(probability[1]),
        "prediction": int(prediction),
        "risk_level": risk_level,
        "model_type": model_type,
        "metrics": metrics
    }


print("=" * 80)
print("PRUEBA DEL MODELO DE DETECCIÓN DE VULNERABILIDADES")
print("=" * 80)

# Verificar que existe el modelo
if not os.path.exists(MODEL_PATH):
    print(f"\n❌ ERROR: No se encontró el modelo en {MODEL_PATH}")
    print("   Por favor, ejecuta primero: python train_integrated_model.py")
    sys.exit(1)

# Cargar información del modelo
if os.path.exists(METADATA_PATH):
    with open(METADATA_PATH, 'r') as f:
        metadata = json.load(f)
    
    print(f"\n📊 Información del modelo:")
    print(f"   Tipo: {metadata.get('model_type', 'unknown')}")
    print(f"   Precisión (CV): {metadata.get('cv_accuracy', 0):.2%}")
    print(f"   Precisión (Test): {metadata.get('test_accuracy', 0):.2%}")
    print(f"   F1-Score: {metadata.get('test_f1', 0):.2%}")
    print(f"   AUC: {metadata.get('test_auc', 0):.2%}")

results = []

for filename, expected_risk in test_files:
    file_path = Path(filename)
    
    if not file_path.exists():
        print(f"\n⚠️ Archivo no encontrado: {filename}")
        print(f"   Por favor, crea el archivo primero")
        continue
    
    print(f"\n{'='*80}")
    print(f"📄 Analizando: {filename}")
    print(f"🎯 Riesgo esperado: {expected_risk}")
    print(f"{'='*80}")
    
    try:
        # Obtener predicción con detalles
        result = predict_risk_detailed(str(file_path))
        
        if "error" in result:
            print(f"\n❌ ERROR: {result['error']}")
            continue
        
        # Mostrar resultados
        print(f"\n✅ RESULTADOS:")
        print(f"   Probabilidad de vulnerabilidad: {result['risk_probability']:.4f} ({result['risk_probability']*100:.2f}%)")
        print(f"   Predicción: {'VULNERABLE' if result['prediction'] == 1 else 'SEGURO'}")
        print(f"   Nivel de riesgo: {result['risk_level']}")
        print(f"   Modelo usado: {result['model_type']}")
        
        # Métricas clave
        metrics = result['metrics']
        print(f"\n📊 MÉTRICAS CLAVE:")
        print(f"   LOC: {metrics.get('loc', 0)}")
        print(f"   Funciones: {metrics.get('functions', 0)}")
        print(f"   Clases: {metrics.get('classes', 0)}")
        print(f"   Importaciones: {metrics.get('imports', 0)}")
        print(f"   Complejidad ciclomática: {metrics.get('cyclomatic_complexity', 0)}")
        print(f"   Índice de mantenibilidad: {metrics.get('maintainability_index', 0):.2f}")
        print(f"   Estructuras de control: {metrics.get('control_structures', 0)}")
        
        # Verificar si coincide con expectativa
        expected_prob = {
            "ALTO": (0.7, 1.0),
            "MEDIO": (0.3, 0.7),
            "BAJO": (0.0, 0.3)
        }
        
        prob = result['risk_probability']
        min_prob, max_prob = expected_prob[expected_risk]
        
        if min_prob <= prob <= max_prob:
            print(f"\n✅ RESULTADO CORRECTO: El modelo clasificó correctamente el riesgo como {expected_risk}")
        else:
            print(f"\n⚠️ DISCREPANCIA: Se esperaba riesgo {expected_risk} pero el modelo predijo {result['risk_level']}")
        
        results.append({
            'file': filename,
            'expected': expected_risk,
            'predicted': result['risk_level'],
            'probability': result['risk_probability'],
            'correct': min_prob <= prob <= max_prob
        })
        
    except Exception as e:
        print(f"\n❌ ERROR al analizar {filename}: {e}")
        import traceback
        traceback.print_exc()


# Resumen final
print(f"\n{'='*80}")
print(f"RESUMEN DE PRUEBAS")
print(f"{'='*80}")

if results:
    print(f"\n{'Archivo':<30} {'Esperado':<12} {'Predicho':<12} {'Probabilidad':<15} {'Correcto'}")
    print("-" * 80)
    
    for r in results:
        correct_icon = "✅" if r['correct'] else "❌"
        print(f"{r['file']:<30} {r['expected']:<12} {r['predicted']:<12} {r['probability']:.4f} ({r['probability']*100:.1f}%)    {correct_icon}")
    
    # Estadísticas
    correct_count = sum(1 for r in results if r['correct'])
    total_count = len(results)
    accuracy = correct_count / total_count * 100 if total_count > 0 else 0
    
    print(f"\n📊 ESTADÍSTICAS:")
    print(f"   Total de pruebas: {total_count}")
    print(f"   Predicciones correctas: {correct_count}")
    print(f"   Precisión en pruebas: {accuracy:.1f}%")
    
    if accuracy == 100:
        print(f"\n🎉 ¡EXCELENTE! El modelo clasificó correctamente todos los casos de prueba")
    elif accuracy >= 66:
        print(f"\n✅ BIEN! El modelo tiene buen desempeño en los casos de prueba")
    else:
        print(f"\n⚠️ El modelo necesita ajustes. Considera reentrenar con más datos")

else:
    print("\n⚠️ No se pudieron analizar los archivos de prueba")
    print("   Verifica que los archivos existan y que el modelo esté entrenado")

print(f"\n{'='*80}")