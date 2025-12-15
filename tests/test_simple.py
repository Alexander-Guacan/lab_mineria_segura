import json
import math

# Función para eliminar los valores NaN
def remove_nan(data):
    if isinstance(data, dict):
        return {key: remove_nan(value) for key, value in data.items() if value is not None and not (isinstance(value, float) and math.isnan(value))}
    elif isinstance(data, list):
        return [remove_nan(item) for item in data if item is not None and not (isinstance(item, float) and math.isnan(item))]
    else:
        return data

# Cargar el archivo JSON
with open('transactions_for_mongo.json', 'r') as file:
    data = json.load(file)

# Eliminar los valores NaN
cleaned_data = remove_nan(data)

# Guardar el archivo limpio
with open('archivo_limpio.json', 'w') as file:
    json.dump(cleaned_data, file, indent=4)

print("Archivo limpio guardado como 'archivo_limpio.json'")
