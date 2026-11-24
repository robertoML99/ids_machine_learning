import subprocess
import pandas as pd
import numpy as np
import tempfile
import os
from pathlib import Path
import shutil
import sys
import csv

# Robustez CSV
try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(2**31 - 1)

# =========================
# Configuración
# =========================
BASE_DIR = Path("/shared-hdd/TFGRManzaneque")
PCAP_DIR = BASE_DIR / "pcap" / "2017"
CSV_DIR  = BASE_DIR / "csv"  / "2017"
OUTPUT_DIR = BASE_DIR / "resultados"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

PCAP_NAME = "Friday-WorkingHours.pcap"

CSV_NAMES = [
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
]

pcap_file = PCAP_DIR / PCAP_NAME

# =========================
# Utilidades
# =========================
def abort(msg):
    print(msg)
    sys.exit(1)

def entropy_bytes(b: bytes) -> float:
    if not b:
        return 0.0
    arr = np.frombuffer(b, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256)
    probs = counts[counts > 0] / arr.size
    return float(-np.sum(probs * np.log2(probs)))

def safe_to_int(v, default=0):
    try:
        if v in (None, "", "nan"):
            return default
        return int(float(v))
    except (ValueError, TypeError):
        return default

def is_hex_string(s: str) -> bool:
    if not s:
        return False
    s = s.strip()
    if not s or s == "0" or (len(s) % 2 != 0):
        return False
    hexchars = "0123456789abcdefABCDEF"
    return all(c in hexchars for c in s)

def proto_code(proto_str) -> int:
    s = str(proto_str).lower()
    if "tcp" in s:
        return 6
    if "udp" in s:
        return 17
    return 0

def reverse_flow_id(flow_id: str) -> str:
    if not isinstance(flow_id, str):
        return ""
    parts = flow_id.split("-", 4)
    if len(parts) != 5:
        return ""
    src_ip, dst_ip, src_p, dst_p, proto = parts
    return f"{dst_ip}-{src_ip}-{dst_p}-{src_p}-{proto}"

def pick_payload_hex_fast(tcp_pl, udp_pl, dat_pl):
    # prioridad: tcp > udp > data
    for v in (tcp_pl, udp_pl, dat_pl):
        if v and v != "nan":
            s = str(v).strip()
            if s and s != "0" and s.lower() != "nan":
                return s.replace(":", "")
    return ""

# =========================
# Chequeos
# =========================
if shutil.which("tshark") is None:
    abort("tshark no está en PATH. Verifica con: tshark -v")

if not pcap_file.exists():
    abort(f"PCAP no encontrado: {pcap_file}")

csv_files = [CSV_DIR / n for n in CSV_NAMES]
for f in csv_files:
    if not f.exists():
        abort(f"CSV original no encontrado: {f}")

# =========================
# 1) tshark (una vez)
# =========================
print("1: Ejecutando tshark y extrayendo campos (incluye payload TCP/UDP)")

tmpfile = tempfile.NamedTemporaryFile(delete=False, suffix=".csv")
tmpfile.close()

tshark_fields = [
    "-T", "fields",
    "-e", "ip.src", "-e", "ip.dst",
    "-e", "tcp.srcport", "-e", "tcp.dstport",
    "-e", "udp.srcport", "-e", "udp.dstport",
    "-e", "frame.len", "-e", "frame.time_relative",
    "-e", "frame.protocols",
    "-e", "tcp.payload", "-e", "udp.payload", "-e", "data.data",
    "-E", "separator=|", "-E", "quote=d", "-E", "header=y"
]

cmd = ["tshark", "-r", str(pcap_file),
       "-Y", "ip && (tcp || udp)",
       "--disable-protocol", "cldap", "--disable-protocol", "ldap"] + tshark_fields

try:
    with open(tmpfile.name, "w") as f_out:
        subprocess.run(cmd, stdout=f_out, stderr=subprocess.PIPE, text=True, check=True)
    print("Extracción tshark completada.")
except subprocess.CalledProcessError as e:
    print("Error tshark.\nstderr:\n", e.stderr)
    os.unlink(tmpfile.name)
    sys.exit(1)

# =========================
# 2) Cargar paquetes
# =========================
print("2: Cargando datos extraídos")

chunks = pd.read_csv(
    tmpfile.name,
    sep="|",
    engine="python",
    dtype=str,
    on_bad_lines="skip",
    na_filter=True,
    keep_default_na=True,
    quoting=csv.QUOTE_MINIMAL,
    chunksize=200_000
)
df = pd.concat(chunks, ignore_index=True)
os.unlink(tmpfile.name)

print(f"{len(df)} paquetes cargados desde {pcap_file.name}.")

expected = ["ip.src","ip.dst","tcp.srcport","tcp.dstport","udp.srcport","udp.dstport",
            "frame.len","frame.time_relative","frame.protocols","tcp.payload","udp.payload","data.data"]
for c in expected:
    if c not in df.columns:
        df[c] = np.nan

for c in ["frame.len","frame.time_relative","tcp.srcport","tcp.dstport","udp.srcport","udp.dstport"]:
    df[c] = pd.to_numeric(df[c], errors="coerce")

def get_src_port(row):
    t = row.get("tcp.srcport", np.nan)
    u = row.get("udp.srcport", np.nan)
    if not np.isnan(t): return safe_to_int(t)
    if not np.isnan(u): return safe_to_int(u)
    return 0

def get_dst_port(row):
    t = row.get("tcp.dstport", np.nan)
    u = row.get("udp.dstport", np.nan)
    if not np.isnan(t): return safe_to_int(t)
    if not np.isnan(u): return safe_to_int(u)
    return 0

df["src_port"] = df.apply(get_src_port, axis=1)
df["dst_port"] = df.apply(get_dst_port, axis=1)
df["protocol"] = df["frame.protocols"].apply(proto_code)

# Flow ID "normal"
df["Flow ID"] = df.apply(
    lambda r: f"{str(r.get('ip.src','')).strip()}-{str(r.get('ip.dst','')).strip()}-{r['src_port']}-{r['dst_port']}-{r['protocol']}",
    axis=1
)

num_flows = df["Flow ID"].nunique()
print(f"{num_flows} flujos identificados (aprox).")

# =========================
# 3) Features por Flow ID
# =========================
print("3: Calculando nuevas características (payload real TCP/UDP + fallback)")

flows = []
processed = 0

for flow_id, group in df.groupby("Flow ID", sort=False):
    payload_agg = bytearray()
    pkt_ent = []

    tcp_arr = group["tcp.payload"].astype(str).to_numpy()
    udp_arr = group["udp.payload"].astype(str).to_numpy()
    dat_arr = group["data.data"].astype(str).to_numpy()

    for i in range(len(group)):
        hx = pick_payload_hex_fast(tcp_arr[i], udp_arr[i], dat_arr[i])
        if not hx or not is_hex_string(hx):
            pkt_ent.append(0.0)
            continue
        try:
            b = bytes.fromhex(hx)
        except ValueError:
            pkt_ent.append(0.0)
            continue

        pkt_ent.append(entropy_bytes(b))
        payload_agg.extend(b)

    flow_entropy = entropy_bytes(bytes(payload_agg))
    pe = np.asarray(pkt_ent, dtype=float) if pkt_ent else np.array([], dtype=float)

    if pe.size:
        pkt_ent_mean = float(pe.mean())
        pkt_ent_std  = float(pe.std())
        pkt_ent_max  = float(pe.max())
        zero_ratio   = float(np.mean(np.isclose(pe, 0.0)))
    else:
        pkt_ent_mean = pkt_ent_std = pkt_ent_max = zero_ratio = 0.0

    if len(payload_agg) > 0:
        b2 = np.frombuffer(bytes(payload_agg), dtype=np.uint8)
        byte_printable_ratio = float(np.mean((b2 >= 32) & (b2 <= 126)))
        byte_nonascii_ratio  = float(np.mean(b2 > 127))
    else:
        byte_printable_ratio = 0.0
        byte_nonascii_ratio  = 0.0

    flows.append({
        "Flow ID": flow_id,
        "Payload Entropy": flow_entropy,
        "Packet Entropy Mean": pkt_ent_mean,
        "Packet Entropy Std": pkt_ent_std,
        "Packet Entropy Max": pkt_ent_max,
        "Packet Entropy Zero Ratio": zero_ratio,
        "Byte Printable Ratio": byte_printable_ratio,
        "Byte NonASCII Ratio": byte_nonascii_ratio,
    })

    processed += 1
    if processed % 2000 == 0:
        print(f"   → Procesados {processed}/{num_flows} flujos...")

new_features = pd.DataFrame(flows)
new_features["Flow ID_rev"] = new_features["Flow ID"].apply(reverse_flow_id)

feat_cols = [c for c in new_features.columns if c not in ("Flow ID", "Flow ID_rev")]

# =========================
# 4) Merge por cada CSV
# =========================
print("4: Generando extendidos para cada CSV de Friday")

for original_csv in csv_files:
    print(f"\n=== Merge: {original_csv.name} ===")

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

    # Merge normal
    combined = original.merge(
        new_features[["Flow ID"] + feat_cols],
        on="Flow ID",
        how="left"
    )

    # Fallback reversed (solo missing)
    missing = combined[feat_cols].isna().all(axis=1)
    if missing.any():
        tmp = original.loc[missing, ["Flow ID"]].merge(
            new_features[["Flow ID_rev"] + feat_cols],
            left_on="Flow ID",
            right_on="Flow ID_rev",
            how="left"
        )
        for c in feat_cols:
            combined.loc[missing, c] = tmp[c].to_numpy()

    combined["NewFeat_Matched"] = combined[feat_cols].notna().any(axis=1)

    for c in feat_cols:
        combined[c] = pd.to_numeric(combined[c], errors="coerce").fillna(0.0)

    out_path = OUTPUT_DIR / (original_csv.stem + "_Extendido.csv")
    combined.to_csv(out_path, index=False)

    total = len(combined)
    matched = int(combined["NewFeat_Matched"].sum())
    print(f"→ Archivo generado: {out_path}")
    print(f"→ Resumen: filas={total}, filas_con_features={matched} ({matched/total*100:.2f}%)")
