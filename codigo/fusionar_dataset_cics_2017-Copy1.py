import pandas as pd
import glob
import os

INPUT_DIR = "/shared-hdd/TFGRManzaneque/csv"
OUTPUT_CSV = "/shared-hdd/TFGRManzaneque/resultados/dataset_original_cics_2017.csv"

if os.path.exists(OUTPUT_CSV):
    print(f"Borrando CSV previo: {OUTPUT_CSV}")
    os.remove(OUTPUT_CSV)

csv_files = glob.glob(os.path.join(INPUT_DIR, "*.csv"))

dfs = []

for csv in csv_files:
    print(f"Leyendo: {os.path.basename(csv)}")
    df = pd.read_csv(csv, low_memory=False)

    # Normalizar nombres de columnas
    df.columns = df.columns.str.strip()

    # Filtrar flujos válidos
    if "NewFeat_Matched" not in df.columns:
        raise ValueError(f"Falta NewFeat_Matched en {csv}")

    df = df[df["NewFeat_Matched"] == True]
    dfs.append(df)

merged_df = pd.concat(dfs, ignore_index=True)

# Eliminar columna auxiliar
merged_df = merged_df.drop(columns=["NewFeat_Matched"])

# ---- Duplicados ----
print("\nDuplicados (antes):", merged_df.duplicated().sum())

merged_df = merged_df.drop_duplicates()

print("Duplicados (después):", merged_df.duplicated().sum())
print("Filas tras borrar duplicados:", len(merged_df))

# Guardar
merged_df.to_csv(OUTPUT_CSV, index=False)

print(f"\nCSV final guardado en: {OUTPUT_CSV}")
print(f"Total flujos finales: {len(merged_df)}")
