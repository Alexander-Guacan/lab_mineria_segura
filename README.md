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
6. Verificar datasets generados en:
data/meta/

## 📄 Licencia

Proyecto académico — uso educativo.