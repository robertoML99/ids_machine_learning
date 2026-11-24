import matplotlib.pyplot as plt
from matplotlib import font_manager
import numpy as np
import pandas as pd

# =========================
# Configuración de fuente
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
# Importancias experimento 1
# =========================

importance_exp1 = {
    "Service port": 0.064229,
    "Byte Printable Ratio": 0.060286,
    "Packet Entropy Max": 0.052315,
    "Payload Entropy": 0.045763,
    "Packet Entropy Zero Ratio": 0.041578,
    "Packet Entropy Mean": 0.037512,
    "Packet Entropy Std": 0.030122,
    "Byte NonASCII Ratio": 0.024827,
    "Packet Length Mean": 0.021931,
    "Bwd Packets/s": 0.021271,
    "Bwd Packet Length Max": 0.018952,
    "Max Packet Length": 0.018361,
    "Flow IAT Mean": 0.017571,
    "Subflow Bwd Bytes": 0.017502,
    "Total Length of Bwd Packets": 0.017425,
    "Average Packet Size": 0.017367,
    "Flow IAT Std": 0.016806,
    "Subflow Fwd Bytes": 0.016577,
    "Avg Bwd Segment Size": 0.015935,
    "Bwd Packet Length Mean": 0.015912
}

# =========================
# Importancias experimento 2
# =========================

importance_exp2 = {
    "Service port": 0.067848,
    "Byte Printable Ratio": 0.059932,
    "Packet Entropy Max": 0.053482,
    "Payload Entropy": 0.052104,
    "Packet Entropy Zero Ratio": 0.048695,
    "Packet Entropy Mean": 0.042414,
    "Packet Entropy Std": 0.033864,
    "Byte NonASCII Ratio": 0.022165,
    "Bwd Packets/s": 0.020890,
    "Flow IAT Mean": 0.020516,
    "Flow IAT Std": 0.018306,
    "min_seg_size_forward": 0.018261,
    "Average Packet Size": 0.017193,
    "Flow Packets/s": 0.017141,
    "Fwd IAT Mean": 0.016828,
    "Flow Bytes/s": 0.016581,
    "Fwd Packet Length Max": 0.016357,
    "Max Packet Length": 0.016207,
    "Subflow Fwd Bytes": 0.015813,
    "Fwd IAT Total": 0.015427
}

# =========================
# Quedarse solo con las características comunes
# =========================

common_features = sorted(set(importance_exp1.keys()) & set(importance_exp2.keys()))

df_plot = pd.DataFrame({
    "Experimento 1": {f: importance_exp1[f] for f in common_features},
    "Experimento 2": {f: importance_exp2[f] for f in common_features}
})

# Ordenar por la media de importancia
df_plot["Media"] = df_plot[["Experimento 1", "Experimento 2"]].mean(axis=1)
df_plot = df_plot.sort_values("Media", ascending=False)

# Invertir para que la más importante salga arriba en barh
df_plot = df_plot.sort_values("Media", ascending=True)

# =========================
# Gráfico
# =========================

y = np.arange(len(df_plot))
height = 0.38

fig, ax = plt.subplots(figsize=(12, 8))

bars1 = ax.barh(
    y - height / 2,
    df_plot["Experimento 1"],
    height,
    label="Experimento 1"
)

bars2 = ax.barh(
    y + height / 2,
    df_plot["Experimento 2"],
    height,
    label="Experimento 2"
)

ax.set_yticks(y)
ax.set_yticklabels(df_plot.index)

ax.set_xlabel("Importancia")
ax.set_ylabel("Característica")
ax.set_title("Comparación de características comunes entre experimentos")
ax.legend()

# Espacio extra a la derecha para mostrar valores
max_val = max(df_plot["Experimento 1"].max(), df_plot["Experimento 2"].max())
ax.set_xlim(0, max_val + 0.012)

# Añadir valores numéricos
for bar in bars1:
    width = bar.get_width()
    ax.text(
        width + 0.0005,
        bar.get_y() + bar.get_height() / 2,
        f"{width:.4f}",
        va="center",
        fontsize=8
    )

for bar in bars2:
    width = bar.get_width()
    ax.text(
        width + 0.0005,
        bar.get_y() + bar.get_height() / 2,
        f"{width:.4f}",
        va="center",
        fontsize=8
    )

plt.tight_layout()

plt.savefig(
    "comparacion_feature_importance_comunes.pdf",
    format="pdf",
    bbox_inches="tight"
)

plt.show()