import os
import numpy as np
import pandas as pd

BASE_DIR = "/shared-hdd/TFGRManzaneque/resultados"
csv_path = os.path.join(BASE_DIR, "dataset_final_cics_2017.csv")

df = pd.read_csv(csv_path)

col = "Flow Bytes/s"
if col not in df.columns:
    raise ValueError(f"No existe la columna '{col}' en el CSV.")

# Considera inf como NaN para el chequeo
s = df[col].replace([np.inf, -np.inf], np.nan)
mask_nan = s.isna()

print(f"Total filas: {len(df)}")
print(f"NaN/inf en '{col}': {mask_nan.sum()}")

print("\nNaN/inf por Label (conteo):")
print(df.loc[mask_nan, "Label"].value_counts(dropna=False))

print("\nNaN/inf por Label (porcentaje dentro de las filas con NaN):")
print((df.loc[mask_nan, "Label"].value_counts(dropna=False) / mask_nan.sum() * 100).round(3))