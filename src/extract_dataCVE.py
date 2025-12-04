import pandas as pd

# leer en chunks para no saturar la memoria
chunks = pd.read_csv("data/cvefixes/raw/CVEFixes.csv", chunksize=10000)

sample = pd.concat(chunk.sample(100) for chunk in chunks)  # 100 por bloque
sample = sample.sample(100)  # tomar solo 1000 al final

sample.to_csv("muestra_aleatoria.csv", index=False)
