import argparse
import pandas as pd


COLUMNAS = [
    "Flow ID",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
]


def main(ruta_csv):
    # Cargar CSV
    df = pd.read_csv(ruta_csv, low_memory=False)

    # Quitar espacios al inicio/final de los nombres de columnas
    # Muy útil porque algunos CSV de CICIDS tienen columnas como " Source IP"
    df.columns = df.columns.str.strip()

    # Comprobar que existen las columnas
    columnas_faltantes = [col for col in COLUMNAS if col not in df.columns]
    if columnas_faltantes:
        raise ValueError(f"Faltan columnas en el CSV: {columnas_faltantes}")

    # Limpiar espacios en valores de texto
    for col in COLUMNAS:
        if df[col].dtype == "object":
            df[col] = df[col].str.strip()

    total_filas = len(df)

    # Filas cuya combinación de valores aparece más de una vez
    filas_repetidas = df.duplicated(subset=COLUMNAS, keep=False).sum()

    # Duplicados extra, es decir, repeticiones sin contar la primera aparición
    duplicados_extra = df.duplicated(subset=COLUMNAS, keep="first").sum()

    ratio_filas_repetidas = filas_repetidas / total_filas
    ratio_duplicados_extra = duplicados_extra / total_filas

    print(f"Total de filas: {total_filas}")
    print(f"Filas con valores repetidos en esas columnas: {filas_repetidas}")
    print(f"Ratio de filas repetidas: {ratio_filas_repetidas:.6f}")
    print(f"Porcentaje de filas repetidas: {ratio_filas_repetidas * 100:.2f}%")

    print()
    print(f"Duplicados extra sin contar la primera aparición: {duplicados_extra}")
    print(f"Ratio de duplicados extra: {ratio_duplicados_extra:.6f}")
    print(f"Porcentaje de duplicados extra: {ratio_duplicados_extra * 100:.2f}%")

    print()
    print("Top 10 combinaciones más repetidas:")
    conteos = (
        df.groupby(COLUMNAS)
        .size()
        .reset_index(name="repeticiones")
        .sort_values("repeticiones", ascending=False)
        .head(10)
    )

    print(conteos.to_string(index=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", help="Ruta al fichero CSV")
    args = parser.parse_args()

    main(args.csv)