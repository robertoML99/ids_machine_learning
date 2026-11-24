import os
import pandas as pd

BASE_DIR = "/shared-hdd/TFGRManzaneque/resultados"

csv_path = os.path.join(BASE_DIR, "dataset_final_cics_2017.csv")
csv_salida = os.path.join(BASE_DIR, "dataset_final_cics_2017_sin_duplicados.csv")

# Leer CSV original
df = pd.read_csv(csv_path)

# Contar filas originales
filas_originales = len(df)

# Eliminar duplicados por Flow ID usando groupby + first()
df_sin_duplicados = (
    df.groupby("Flow ID", as_index=False, sort=False, dropna=False)
      .first()
)

# Contar filas después
filas_despues = len(df_sin_duplicados)

# Guardar nuevo CSV sin modificar el original
df_sin_duplicados.to_csv(csv_salida, index=False)

print(f"Filas originales: {filas_originales}")
print(f"Filas después de eliminar duplicados por Flow ID: {filas_despues}")
print(f"Duplicados eliminados: {filas_originales - filas_despues}")
print(f"CSV generado en: {csv_salida}")