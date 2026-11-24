import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib import font_manager

# =========================
# Rutas
# =========================

BASE_DIR = "/shared-hdd/TFGRManzaneque/resultados"
csv_path = os.path.join(BASE_DIR, "dataset_final_cics_2017.csv")

OUT_DIR = os.path.join(BASE_DIR, "analisis_exploratorio")
os.makedirs(OUT_DIR, exist_ok=True)

df = pd.read_csv(csv_path)

# =========================
# Fuente para gráficas
# =========================

fuentes_preferidas = [
    "Times New Roman",
    "Nimbus Roman",
    "Liberation Serif",
    "TeX Gyre Termes",
    "DejaVu Serif"
]

fuentes_disponibles = {f.name for f in font_manager.fontManager.ttflist}

for fuente in fuentes_preferidas:
    if fuente in fuentes_disponibles:
        fuente_elegida = fuente
        break
else:
    fuente_elegida = "serif"

print("Fuente utilizada:", fuente_elegida)

plt.rcParams["font.family"] = "serif"
plt.rcParams["font.serif"] = [fuente_elegida]
plt.rcParams["pdf.fonttype"] = 42
plt.rcParams["ps.fonttype"] = 42


# =========================
# 1. Resumen general del dataset
# =========================

num_muestras = len(df)
num_columnas = df.shape[1]
num_clases = df["Label"].nunique()
num_columnas_numericas = df.select_dtypes(include=[np.number]).shape[1]
num_columnas_no_numericas = df.shape[1] - num_columnas_numericas

num_flow_ids_unicos = df["Flow ID"].nunique()
conteo_flow_ids = df["Flow ID"].value_counts()

num_flow_ids_repetidos = (conteo_flow_ids > 1).sum()
num_registros_en_flow_ids_repetidos = df["Flow ID"].isin(
    conteo_flow_ids[conteo_flow_ids > 1].index
).sum()

porcentaje_registros_flow_repetidos = (
    100 * num_registros_en_flow_ids_repetidos / num_muestras
)

max_registros_mismo_flow_id = conteo_flow_ids.max()

tabla_resumen = pd.DataFrame({
    "Métrica": [
        "Número de muestras",
        "Número de columnas",
        "Número de columnas numéricas",
        "Número de columnas no numéricas",
        "Número de clases",
        "Número de Flow ID únicos",
        "Número de Flow ID repetidos",
        "Registros pertenecientes a Flow ID repetidos",
        "Porcentaje de registros en Flow ID repetidos",
        "Máximo número de registros con el mismo Flow ID"
    ],
    "Valor": [
        num_muestras,
        num_columnas,
        num_columnas_numericas,
        num_columnas_no_numericas,
        num_clases,
        num_flow_ids_unicos,
        num_flow_ids_repetidos,
        num_registros_en_flow_ids_repetidos,
        round(porcentaje_registros_flow_repetidos, 4),
        max_registros_mismo_flow_id
    ]
})

print("\nResumen general del dataset:")
print(tabla_resumen)

tabla_resumen.to_csv(
    os.path.join(OUT_DIR, "tabla_resumen_dataset.csv"),
    index=False
)

tabla_resumen.to_latex(
    os.path.join(OUT_DIR, "tabla_resumen_dataset.tex"),
    index=False,
    caption="Resumen general del conjunto de datos final.",
    label="tab:resumen_dataset"
)


# =========================
# 2. Distribución de clases
# =========================

tabla_clases = df["Label"].value_counts().reset_index()
tabla_clases.columns = ["Clase", "Número de muestras"]
tabla_clases["Porcentaje"] = (
    100 * tabla_clases["Número de muestras"] / len(df)
).round(4)

print("\nDistribución de clases:")
print(tabla_clases)

tabla_clases.to_csv(
    os.path.join(OUT_DIR, "tabla_distribucion_clases.csv"),
    index=False
)

tabla_clases.to_latex(
    os.path.join(OUT_DIR, "tabla_distribucion_clases.tex"),
    index=False,
    caption="Distribución de clases en el conjunto de datos final.",
    label="tab:distribucion_clases",
    float_format="%.4f"
)


# =========================
# 3. Gráfica de distribución de clases
# =========================

dist = df["Label"].value_counts()

fig, ax = plt.subplots(figsize=(10, 6))

bars = ax.bar(dist.index, dist.values)

ax.set_title("Distribución de clases del conjunto de datos", fontsize=14)
ax.set_xlabel("Clase", fontsize=12)
ax.set_ylabel("Número de muestras", fontsize=12)

# Escala logarítmica para que se vean las clases minoritarias
ax.set_yscale("log")

plt.xticks(rotation=45, ha="right")

# Añadir el valor exacto encima de cada barra
for bar, valor in zip(bars, dist.values):
    ax.text(
        bar.get_x() + bar.get_width() / 2,
        valor * 1.08,  # un poco por encima de la barra
        str(valor),
        ha="center",
        va="bottom",
        fontsize=9
    )

plt.tight_layout()

plt.savefig(
    os.path.join(OUT_DIR, "distribucion_clases.pdf"),
    format="pdf",
    bbox_inches="tight"
)

plt.show()


# =========================
# 4. Flow ID repetidos por clase
# =========================

flow_ids_repetidos = conteo_flow_ids[conteo_flow_ids > 1].index
df_flow_repetidos = df[df["Flow ID"].isin(flow_ids_repetidos)]

tabla_flow_repetidos_clase = df_flow_repetidos["Label"].value_counts().reset_index()
tabla_flow_repetidos_clase.columns = ["Clase", "Registros con Flow ID repetido"]
tabla_flow_repetidos_clase["Porcentaje sobre clase"] = tabla_flow_repetidos_clase.apply(
    lambda row: 100 * row["Registros con Flow ID repetido"] / (df["Label"] == row["Clase"]).sum(),
    axis=1
).round(4)

print("\nRegistros con Flow ID repetido por clase:")
print(tabla_flow_repetidos_clase)

tabla_flow_repetidos_clase.to_csv(
    os.path.join(OUT_DIR, "tabla_flowid_repetidos_por_clase.csv"),
    index=False
)

tabla_flow_repetidos_clase.to_latex(
    os.path.join(OUT_DIR, "tabla_flowid_repetidos_por_clase.tex"),
    index=False,
    caption="Registros pertenecientes a Flow ID repetidos por clase.",
    label="tab:flowid_repetidos_clase",
    float_format="%.4f"
)


# =========================
# 5. Comprobación de etiquetas dentro de Flow ID repetidos
# =========================

labels_por_flow = df.groupby("Flow ID")["Label"].nunique()
flow_ids_con_multiples_labels = labels_por_flow[labels_por_flow > 1]

tabla_consistencia_flowid = pd.DataFrame({
    "Métrica": [
        "Flow ID con más de una etiqueta",
        "Porcentaje sobre Flow ID únicos"
    ],
    "Valor": [
        len(flow_ids_con_multiples_labels),
        round(100 * len(flow_ids_con_multiples_labels) / num_flow_ids_unicos, 4)
    ]
})

print("\nConsistencia de etiquetas por Flow ID:")
print(tabla_consistencia_flowid)

tabla_consistencia_flowid.to_csv(
    os.path.join(OUT_DIR, "tabla_consistencia_flowid.csv"),
    index=False
)

tabla_consistencia_flowid.to_latex(
    os.path.join(OUT_DIR, "tabla_consistencia_flowid.tex"),
    index=False,
    caption="Consistencia de etiquetas asociadas a un mismo Flow ID.",
    label="tab:consistencia_flowid"
)


# =========================
# 6. Listado de características
# =========================

columnas_identificacion = [
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Source Port",
    "Destination Port",
    "Timestamp",
    "Label"
]

caracteristicas_modelo = [
    col for col in df.columns
    if col not in columnas_identificacion
]

tabla_caracteristicas = pd.DataFrame({
    "Tipo": [
        "Columnas totales",
        "Columnas de identificación o etiqueta",
        "Características disponibles para el análisis/modelo"
    ],
    "Número": [
        len(df.columns),
        len([c for c in columnas_identificacion if c in df.columns]),
        len(caracteristicas_modelo)
    ]
})

print("\nResumen de características:")
print(tabla_caracteristicas)

tabla_caracteristicas.to_csv(
    os.path.join(OUT_DIR, "tabla_resumen_caracteristicas.csv"),
    index=False
)

tabla_caracteristicas.to_latex(
    os.path.join(OUT_DIR, "tabla_resumen_caracteristicas.tex"),
    index=False,
    caption="Resumen de columnas y características del conjunto de datos.",
    label="tab:resumen_caracteristicas"
)


print("\nArchivos generados en:", OUT_DIR)