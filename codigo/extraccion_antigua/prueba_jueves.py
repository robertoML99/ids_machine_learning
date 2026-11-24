import pandas as pd, csv

f = "/shared-hdd/TFGRManzaneque/csv/2017/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
df0 = pd.read_csv(f, engine="python", dtype=str, on_bad_lines="skip", encoding="latin-1", quoting=csv.QUOTE_MINIMAL)

prot = pd.to_numeric(df0[" Protocol"], errors="coerce").fillna(-1).astype(int)
sp   = pd.to_numeric(df0[" Source Port"], errors="coerce").fillna(-1).astype(int)
dp   = pd.to_numeric(df0[" Destination Port"], errors="coerce").fillna(-1).astype(int)

matcheable = prot.isin([6,17]) & (sp > 0) & (dp > 0)

print("Total filas:", len(df0))
print("% matcheables (TCP/UDP + puertos>0):", matcheable.mean()*100)
print("Top Protocols:\n", prot.value_counts().head(10))
