import matplotlib.pyplot as plt
from matplotlib import font_manager

# =========================
# Configuración de fuentes
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
# Datos de feature importance
# =========================

features = [
    "Service port",
    "Byte Printable Ratio",
    "Packet Entropy Max",
    "Payload Entropy",
    "Packet Entropy Zero Ratio",
    "Packet Entropy Mean",
    "Packet Entropy Std",
    "Byte NonASCII Ratio",
    "Bwd Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "min_seg_size_forward",
    "Average Packet Size",
    "Flow Packets/s",
    "Fwd IAT Mean",
    "Flow Bytes/s",
    "Fwd Packet Length Max",
    "Max Packet Length",
    "Subflow Fwd Bytes",
    "Fwd IAT Total"
]

importances = [
    0.067848,
    0.059932,
    0.053482,
    0.052104,
    0.048695,
    0.042414,
    0.033864,
    0.022165,
    0.020890,
    0.020516,
    0.018306,
    0.018261,
    0.017193,
    0.017141,
    0.016828,
    0.016581,
    0.016357,
    0.016207,
    0.015813,
    0.015427
]


# =========================
# Gráfica
# =========================

# Invertir para que la más importante salga arriba
features_plot = features[::-1]
importances_plot = importances[::-1]

plt.figure(figsize=(10, 8))
plt.barh(features_plot, importances_plot)

plt.xlabel("Importancia de la característica")
plt.ylabel("Características")
plt.title("Importancia de características obtenida con Random Forest")

# Añadir valores numéricos
for i, value in enumerate(importances_plot):
    plt.text(
        value + 0.0005,
        i,
        f"{value:.6f}",
        va="center",
        fontsize=9
    )

plt.tight_layout()

plt.savefig(
    "feature_importance_2.pdf",
    format="pdf",
    bbox_inches="tight"
)

plt.close()