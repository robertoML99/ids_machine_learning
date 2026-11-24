import subprocess
import pandas as pd
import numpy as np
import tempfile
import os
from pathlib import Path
import shutil
import sys
import csv

# Aumentar el límite de tamaño por campo para el parser Python usado por pandas
try:
    csv.field_size_limit(sys.maxsize)      # lo máximo que permita la plataforma
except OverflowError:
    csv.field_size_limit(2**31 - 1)        # fallback seguro en 32-bit

# =========================
# Configuración de rutas
# =========================
BASE_DIR = Path("/shared-hdd/TFGRManzaneque")
PCAP_DIR = BASE_DIR / "pcap" / "2017"
CSV_DIR  = BASE_DIR / "csv"  / "2017"
OUTPUT_DIR = BASE_DIR / "resultados"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

pcap_file    = PCAP_DIR / "Monday-WorkingHours.pcap"
original_csv = CSV_DIR  / "Monday-WorkingHours.pcap_ISCX.csv"
output_csv   = OUTPUT_DIR / "Monday-WorkingHours_Extendido.csv"

# =========================
# Utilidades
# =========================
def abort(msg):
    print(msg)
    sys.exit(1)

def entropy(byte_seq):
    """Entropía de Shannon en base 2 sobre una secuencia de bytes."""
    if not byte_seq:
        return 0.0
    counts = np.bincount(byte_seq, minlength=256)
    probs = counts[counts > 0] / len(byte_seq)
    return float(-np.sum(probs * np.log2(probs)))

def safe_to_int(v, default=0):
    """Convierte a int de forma robusta (admite '', None, '0.0', etc.)."""
    try:
        if v in (None, "", "nan"):
            return default
        return int(float(v))
    except (ValueError, TypeError):
        return default

def is_hex_string(s):
    """True si s es una cadena hexadecimal válida con longitud par."""
    if not s:
        return False
    s = s.strip()
    if not s or s == "0" or (len(s) % 2 != 0):
        return False
    hexchars = "0123456789abcdefABCDEF"
    return all(c in hexchars for c in s)

# =========================
# Chequeos previos
# =========================
if shutil.which("tshark") is None:
    abort("tshark no está en PATH. Ejecuta 'tshark -v' en la terminal para verificar instalación.")

if not pcap_file.exists():
    abort(f"PCAP no encontrado: {pcap_file}")

if not original_csv.exists():
    abort(f"CSV original no encontrado: {original_csv}")

# =========================
# 1) Ejecutar tshark
# =========================
print("1: Ejecutando tshark y extrayendo campos necesarios")

tmpfile = tempfile.NamedTemporaryFile(delete=False, suffix=".csv")
tshark_fields = [
    "-T", "fields",
    "-e", "ip.src", "-e", "ip.dst",
    "-e", "tcp.srcport", "-e", "tcp.dstport",
    "-e", "udp.srcport", "-e", "udp.dstport",
    "-e", "frame.len", "-e", "frame.time_relative",
    "-e", "frame.protocols", "-e", "data.data",
    "-E", "separator=|", "-E", "quote=d", "-E", "header=y"
]

try:
    with open(tmpfile.name, "w") as f_out:
        subprocess.run(
            ["tshark", "-r", str(pcap_file)]
            + ["--disable-protocol", "cldap", "--disable-protocol", "ldap"]
            + tshark_fields,
            stdout=f_out,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
    print("Extracción completada correctamente.")
except subprocess.CalledProcessError as e:
    print("Error al ejecutar tshark.")
    print("Comando:", e.cmd)
    print("Código de retorno:", e.returncode)
    print("stderr:\n", e.stderr)
    os.unlink(tmpfile.name)
    sys.exit(1)

# =========================
# 2) Cargar CSV de tshark (robusto)
# =========================
print("2: Cargando datos extraídos")

# Usamos engine="python" + chunks para evitar segfault y reducir memoria
chunks = pd.read_csv(
    tmpfile.name,
    sep="|",
    engine="python",
    dtype=str,                # Leemos todo como texto y casteamos después
    on_bad_lines="skip",      # Ignora líneas corruptas si las hubiera
    na_filter=True,
    keep_default_na=True,
    quoting=csv.QUOTE_MINIMAL,
    chunksize=200_000         # Ajusta según RAM disponible
)
df = pd.concat(chunks, ignore_index=True)
os.unlink(tmpfile.name)
print(f"{len(df)} paquetes cargados desde {pcap_file.name}.")

# =========================
# 3) Procesamiento de campos
# =========================
print("3: Procesando campos de red y protocolos.")

# Aseguramos columnas esperadas
for col in ["ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "frame.len", "frame.time_relative", "frame.protocols", "data.data"]:
    if col not in df.columns:
        df[col] = np.nan

# Conversión de numéricos de forma controlada
for col in ["frame.len", "frame.time_relative", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"]:
    df[col] = pd.to_numeric(df[col], errors="coerce")

# Puertos origen/destino robustos
def get_src_port(row):
    return safe_to_int(row.get("tcp.srcport")) if not np.isnan(row.get("tcp.srcport", np.nan)) else (
        safe_to_int(row.get("udp.srcport")) if not np.isnan(row.get("udp.srcport", np.nan)) else 0
    )

def get_dst_port(row):
    return safe_to_int(row.get("tcp.dstport")) if not np.isnan(row.get("tcp.dstport", np.nan)) else (
        safe_to_int(row.get("udp.dstport")) if not np.isnan(row.get("udp.dstport", np.nan)) else 0
    )

df["src_port"] = df.apply(get_src_port, axis=1)
df["dst_port"] = df.apply(get_dst_port, axis=1)

# Protocolo como 6 (TCP), 17 (UDP) o 0
def proto_code(proto_str):
    s = str(proto_str).lower()
    if "tcp" in s:
        return 6
    if "udp" in s:
        return 17
    return 0

df["protocol"] = df["frame.protocols"].apply(proto_code)

# Flow ID
df["Flow ID"] = df.apply(
    lambda r: f"{r.get('ip.dst','')}-{r.get('ip.src','')}-{r['dst_port']}-{r['src_port']}-{r['protocol']}",
    axis=1
)

num_flows = df["Flow ID"].nunique()
print(f"{num_flows} flujos identificados.")

# =========================
# 4) Cálculo de nuevas características
# =========================
print("4: Calculando nuevas características")
flows = []
processed = 0

# Por rendimiento, evitamos astype() dentro del bucle si es posible
# Convertimos una sola vez las columnas numéricas necesarias
df["frame.len"] = pd.to_numeric(df["frame.len"], errors="coerce")
df["frame.time_relative"] = pd.to_numeric(df["frame.time_relative"], errors="coerce")

for flow_id, group in df.groupby("Flow ID", sort=False):
    # Reconstrucción del payload en bytes
    payload_bytes = []
    for payload_hex in group["data.data"]:
        if pd.isna(payload_hex):
            continue
        s = str(payload_hex).strip()
        if not is_hex_string(s):
            continue
        try:
            payload_bytes.extend(bytes.fromhex(s))
        except ValueError:
            # Si a pesar del filtro algo falla, lo ignoramos
            continue
            
    # Calcular entropia de paquete individual, min y max de paquete
    # Añadir cosas gepeto
    # trastear con pl
    
    # Entropía
    flow_entropy = entropy(payload_bytes)

    # Estadísticos de longitudes
    packet_lengths = group["frame.len"].astype(float).values
    packet_lengths = packet_lengths[~np.isnan(packet_lengths)]
    pl_mean = float(np.mean(packet_lengths)) if packet_lengths.size > 0 else 0.0
    pl_std  = float(np.std(packet_lengths))  if packet_lengths.size > 0 else 0.0

    # Duración del flujo y PPS
    times = group["frame.time_relative"].astype(float).values
    times = times[~np.isnan(times)]
    if times.size > 1:
        duration = float(times.max() - times.min())
    else:
        duration = 0.0
    pps = float(len(group) / duration) if duration > 0 else 0.0

    flows.append({
        "Flow ID": flow_id,
        "Payload Entropy": flow_entropy,
        "Packet Length Mean New": pl_mean,
        "Packet Length Std New": pl_std,
        "Flow Duration New": duration,
        "Packets Per Second New": pps
    })

    processed += 1
    if processed % 500 == 0:
        print(f"   → Procesados {processed}/{num_flows} flujos...")

print(f"Cálculo completado. {len(flows)} flujos procesados.")

# =========================
# 5) Merge con CSV original y guardado
# =========================
print("5: Concatenando CSVs")

# Leemos el CSV original de forma robusta
orig_chunks = pd.read_csv(
    original_csv,
    engine="python",
    dtype=str,
    on_bad_lines="skip",
    na_filter=True,
    keep_default_na=True,
    quoting=csv.QUOTE_MINIMAL,
    chunksize=200_000
)
original = pd.concat(orig_chunks, ignore_index=True)

new_features = pd.DataFrame(flows)

# Merge por Flow ID
combined = pd.merge(original, new_features, on="Flow ID", how="left")

# Elimina solo filas con 'Payload Entropy' NaN (no elimina 0.0)
combined = combined.dropna(subset=["Payload Entropy"])

# Elimina las filas duplicadas, quedandose con el que tenga mas flow duration
combined[" Flow Duration"] = pd.to_numeric(combined[" Flow Duration"], errors="coerce")
idx = combined.groupby("Flow ID")[" Flow Duration"].idxmax()
combined = combined.loc[idx].copy()

# Guardado (sobrescribe si existe)
combined.to_csv(output_csv, index=False)
print(f"Archivo generado correctamente: {output_csv}")
