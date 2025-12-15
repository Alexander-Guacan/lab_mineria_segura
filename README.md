# Laboratorio 1 – Minería de Datos Aplicada al Desarrollo de Software Seguro  
### Universidad de las Fuerzas Armadas ESPE  
**Materia:** Desarrollo de Software Seguro  
**Estudiante:** *[Tu nombre]*  
**Fecha límite:** 2 de diciembre de 2025  

---

## 📌 Descripción del Proyecto

Este laboratorio explora cómo aplicar **técnicas de minería de datos** para identificar **potenciales vulnerabilidades** en código fuente.  
El enfoque sigue la metodología **SEMMA (Sample, Explore, Modify, Model, Assess)** e integra resultados en un proceso **DevSecOps**.

El objetivo final es construir un **modelo predictivo de vulnerabilidades**, entrenarlo con un dataset basado en repositorios reales de GitHub, y posteriormente integrarlo en un pipeline de CI/CD (GitHub Actions).

---

## 📁 Estructura del Proyecto

lab_mineria_segura/
│── data/
│ ├── raw/ # Repos descargados (IGNORADOS EN GIT)
│ ├── commits/ # Commits descargados de la API (IGNORADOS EN GIT)
│ └── meta/ # Datasets generados durante el análisis
│
│── src/
│ ├── download_sample.py # Script Día 2 – SEMMA: Sample
│ └── extract_features.py # (Se desarrollará en el Día 3)
│
│── notebooks/ # Exploraciones Jupyter opcionales
│── docs/ # Documentación del proyecto
│── .gitignore
│── README.md

---

## 📊 Repositorios Analizados

Los datos provienen de cuatro repositorios representativos y ampliamente utilizados:

- `scrapy/scrapy`
- `fastapi/fastapi`
- `pandas-dev/pandas`
- `python/cpython`

Estos repos permiten generar una muestra variada en complejidad, arquitectura y estilos de código.

---

## ⚙️ Requisitos técnicos

- Python 3.10+
- Git
- Librerías:
pandas
numpy
scikit-learn
requests
gitpython
radon
tqdm

---

## 🧑‍💻 Cómo ejecutar

1. Clonar este repositorio  
2. Crear el entorno virtual
 ```bash
 python -m venv .venv
 ```
3. Activar entorno virtual
 ```bash
 # Windows (cmd)
 .venv\Scripts\activate
 ```

 ```bash
 # Windows (Powershell)
 .venv\Scripts\Activate.ps1
 ```

 ```bash
 # Linux/MacOS
 source .venv/bin/activate
 ```
4. Instalar dependencias
 ```bash
 pip install -r requirements.txt
 ```
5. Ejecutar:
 ```bash
 python src/download_sample.py
 ```

 ```bash
 python src/extract_features.py
 ```
6. Verificar datasets generados en:
data/meta/

## Guía de Uso del Modelo Implementado

Este proyecto permite analizar riesgos de seguridad en código fuente utilizando un modelo de machine learning entrenado con datasets de vulnerabilidades. A continuación, se describen los pasos para usar las clases y scripts principales:

---

### 1. Descargar el Dataset de CVEFixes
El script `download_cvefixes.py` descarga el dataset de vulnerabilidades desde fuentes oficiales.

#### Uso:
```bash
python src/download_cvefixes.py
```

#### Qué hace:
- Descarga el archivo `CVEfixes.csv` desde el repositorio oficial o Kaggle.
- Guarda los datos en la carpeta `data/cvefixes/raw/`.

---

### 2. Procesar el Dataset de Kaggle
El script `process_kaggle_dataset.py` procesa el dataset descargado desde Kaggle para convertirlo en un formato compatible con el modelo.

#### Uso:
```bash
python src/process_kaggle_dataset.py
```

#### Qué hace:
- Limpia y transforma los datos del dataset de Kaggle.
- Genera un archivo procesado en `data/cvefixes/processed/`.

---

### 3. Integrar Datasets
El script `integrate_datasets.py` combina múltiples datasets (como CVEFixes y Kaggle) en un único dataset integrado.

#### Uso:
```bash
python src/integrate_datasets.py
```

#### Qué hace:
- Combina los datasets procesados en un único archivo `dataset_integrated.csv`.
- Guarda el archivo integrado en `data/meta/`.

---

### 4. Entrenar el Modelo
El script `train_integrated_model.py` entrena un modelo de machine learning utilizando el dataset integrado.

#### Uso:
```bash
python src/train_integrated_model.py
```

#### Qué hace:
- Entrena un modelo con los datos de `dataset_integrated.csv`.
- Guarda el modelo entrenado en `data/meta/best_model.pkl`.
- Genera un archivo de metadatos del modelo en `data/results/model_metadata.json`.

---

### 5. Probar el Modelo
El script `src/test_model.py` permite probar el modelo entrenado con archivos de código fuente.

#### Uso:
```bash
python src/test_model.py <archivo.py>
```

#### Ejemplo:
```bash
python src/test_model.py tests/vulnerable_code.py
```

#### Qué hace:
- Extrae características del archivo de código.
- Predice la probabilidad de que el archivo sea vulnerable.
- Muestra un resumen con la clasificación y las probabilidades.

#### Salida esperada:
```plaintext
====================================================================
PROBANDO MODELO EN: tests/vulnerable_code.py
====================================================================

📊 Información del modelo:
   Tipo: gradient_boosting
   Precisión (CV): 99.97%
   Precisión (Test): 99.92%
   F1-Score: 99.92%
   AUC: 99.92%

🔍 Extrayendo características del archivo...

📈 Características extraídas:
   loc: 62
   comments: 11
   functions: 6
   classes: 0
   imports: 3
   ast_nodes: 201
   control_structures: 5
   cyclomatic_complexity: 7
   maintainability_index: 82.75
   size_bytes: 1983

====================================================================
RESULTADO DE LA PREDICCIÓN
====================================================================

🎯 Clasificación: ⚠️ VULNERABLE
📊 Probabilidad de ser SEGURO: 0.00%
📊 Probabilidad de ser VULNERABLE: 100.00%

💡 Interpretación:
   🔴 ALTO RIESGO - Revisar urgentemente
```

---

### Resumen del Flujo Completo
1. **Descargar el dataset:** `download_cvefixes.py`
2. **Procesar el dataset de Kaggle:** `process_kaggle_dataset.py`
3. **Integrar datasets:** `integrate_datasets.py`
4. **Entrenar el modelo:** `train_integrated_model.py`
5. **Probar el modelo:** `src/test_model.py`

---

### Notas Adicionales
- Asegúrate de instalar las dependencias del proyecto antes de ejecutar los scripts:
  ```bash
  pip install -r requirements.txt
  ```
- Los resultados del modelo se guardan en la carpeta `data/results/`.

## 📄 Licencia

Proyecto académico — uso educativo.