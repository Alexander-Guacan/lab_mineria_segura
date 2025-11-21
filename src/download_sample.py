import os
import git
import requests
import pandas as pd
from tqdm import tqdm

# ---------------------------------------------------------
# CONFIGURACIÓN
# ---------------------------------------------------------
REPOS = {
    "scrapy": "https://github.com/scrapy/scrapy.git",
    "fastapi": "https://github.com/fastapi/fastapi.git",
    "pandas": "https://github.com/pandas-dev/pandas.git",
    "cpython": "https://github.com/python/cpython.git"
}

# Mapeo directo al nombre real del repositorio en GitHub
REPO_API_NAMES = {
    "scrapy": "scrapy/scrapy",
    "fastapi": "fastapi/fastapi",
    "pandas": "pandas-dev/pandas",
    "cpython": "python/cpython"
}

BASE_DIR = "data/raw"
COMMITS_DIR = "data/commits"
META_PATH = "data/meta/dataset_raw.csv"

os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(COMMITS_DIR, exist_ok=True)
os.makedirs("data/meta", exist_ok=True)


# ---------------------------------------------------------
# FUNCIÓN: Clonar repositorios si no existen
# ---------------------------------------------------------
def clone_or_update_repo(name, url):
    repo_path = os.path.join(BASE_DIR, name)

    if not os.path.exists(repo_path):
        print(f"Clonando {name}...")
        git.Repo.clone_from(url, repo_path)
    else:
        print(f"Actualizando {name}...")
        repo = git.Repo(repo_path)
        repo.remotes.origin.pull()

    return repo_path


# ---------------------------------------------------------
# FUNCIÓN: Obtener últimos commits desde la API de GitHub
# ---------------------------------------------------------
def get_recent_commits(repo_fullname, n=50):
    url = f"https://api.github.com/repos/{repo_fullname}/commits?per_page={n}"
    response = requests.get(url)

    if response.status_code != 200:
        print(f"⚠ No se pudieron obtener commits de {repo_fullname} ({response.status_code})")
        return []

    return response.json()


# ---------------------------------------------------------
# FUNCIÓN: Recorrer archivos .py y generar dataset base
# ---------------------------------------------------------
def scan_python_files(repo_name, repo_path):
    records = []

    for root, dirs, files in os.walk(repo_path):
        for file in files:
            if file.endswith(".py"):
                fpath = os.path.join(root, file)
                try:
                    size = os.path.getsize(fpath)
                except:
                    size = -1

                records.append({
                    "repo": repo_name,
                    "file_path": fpath,
                    "file_name": file,
                    "size_bytes": size
                })

    return records


# ---------------------------------------------------------
# PROCESO PRINCIPAL
# ---------------------------------------------------------
all_records = []

print("\n=== Descargando / Actualizando repos ===")
for name, url in REPOS.items():
    repo_path = clone_or_update_repo(name, url)

    # Obtener commits usando el nombre real del repo en GitHub
    print(f"Obteniendo commits para {name}...")
    commits = get_recent_commits(REPO_API_NAMES[name], 50)

    commits_path = os.path.join(COMMITS_DIR, f"{name}_commits.json")
    pd.Series(commits).to_json(commits_path)

    # Recorrer archivos .py
    print(f"Escaneando archivos .py en {name}...")
    repo_records = scan_python_files(name, repo_path)
    all_records.extend(repo_records)

# Convertir a DataFrame
df = pd.DataFrame(all_records)

print("\nGenerando dataset inicial...")
df.to_csv(META_PATH, index=False)

print("\n=== COMPLETADO ===")
print(f"Archivos escaneados: {len(df)}")
print(f"Dataset creado en: {META_PATH}")
print("Commits guardados en: data/commits/")
