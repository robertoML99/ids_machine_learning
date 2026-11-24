import numpy as np
import matplotlib.pyplot as plt
from matplotlib import font_manager

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
# Matriz de confusión absoluta
# =========================

cm = np.array([
    [566310, 85, 0, 1, 13, 0, 0, 0, 0, 0, 263, 0, 0, 0, 0],
    [24, 467, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1, 0, 32006, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1, 0, 0, 2569, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [2, 0, 0, 5, 57761, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [3, 0, 0, 2, 0, 1364, 6, 0, 0, 0, 0, 0, 0, 0, 0],
    [5, 0, 0, 0, 0, 1, 1443, 0, 0, 0, 0, 0, 0, 0, 0],
    [1, 0, 0, 0, 0, 0, 0, 1984, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0],
    [3, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0],
    [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 39727, 0, 0, 0, 1],
    [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1471, 0, 0, 0],
    [7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 289, 0, 81],
    [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0],
    [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 82, 0, 78]
])

labels = [
    "BENIGN",
    "Bot",
    "DDoS",
    "DoS GoldenEye",
    "DoS Hulk",
    "DoS Slowhttptest",
    "DoS slowloris",
    "FTP-Patator",
    "Heartbleed",
    "Infiltration",
    "PortScan",
    "SSH-Patator",
    "Web Brute Force",
    "Web SQLi",
    "Web XSS"
]


# =========================
# Normalización por filas
# =========================

row_sums = cm.sum(axis=1, keepdims=True)
cm_norm = np.divide(
    cm,
    row_sums,
    out=np.zeros_like(cm, dtype=float),
    where=row_sums != 0
)


# =========================
# Dibujo de la matriz normalizada
# =========================

fig, ax = plt.subplots(figsize=(12, 10))

im = ax.imshow(
    cm_norm,
    interpolation="nearest",
    cmap="Blues",
    vmin=0,
    vmax=1
)

ax.set_title("Matriz de confusión normalizada", fontsize=14)
ax.set_xlabel("Clase predicha", fontsize=12)
ax.set_ylabel("Clase real", fontsize=12)

ax.set_xticks(np.arange(len(labels)))
ax.set_yticks(np.arange(len(labels)))
ax.set_xticklabels(labels, fontsize=9)
ax.set_yticklabels(labels, fontsize=9)

plt.setp(
    ax.get_xticklabels(),
    rotation=45,
    ha="right",
    rotation_mode="anchor"
)

# Rejilla
ax.set_xticks(np.arange(-0.5, len(labels), 1), minor=True)
ax.set_yticks(np.arange(-0.5, len(labels), 1), minor=True)
ax.grid(which="minor", color="gray", linestyle="-", linewidth=0.35)
ax.tick_params(which="minor", bottom=False, left=False)

# Escribir valores normalizados
for i in range(cm_norm.shape[0]):
    for j in range(cm_norm.shape[1]):
        valor = cm_norm[i, j]

        texto = "0" if valor == 0 else f"{valor:.2f}"

        ax.text(
            j,
            i,
            texto,
            ha="center",
            va="center",
            fontsize=7,
            color="white" if valor > 0.5 else "black"
        )

fig.tight_layout()

plt.savefig(
    "matriz_confusion_1_normalizada.pdf",
    format="pdf",
    bbox_inches="tight"
)

plt.show()