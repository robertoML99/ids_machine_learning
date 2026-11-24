import os
import re
import numpy as np
import pandas as pd

from sklearn.model_selection import GroupKFold, RandomizedSearchCV
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, FunctionTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score, f1_score, classification_report,
    confusion_matrix, roc_auc_score
)
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance

RANDOM_STATE = 42

# Juntar todos los csv -> stratify
# Dividir aleatoriamente para las matrices
# --------------------------
# 1) Rutas y ficheros
# --------------------------
BASE_DIR = "/shared-hdd/TFGRManzaneque/csv/2017"

csv_files = [
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
]

csv_paths = [os.path.join(BASE_DIR, f) for f in csv_files]

# --------------------------
# 2) Inferir día desde path
# --------------------------
DAY_ORDER = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
day_regex = re.compile(r"(Monday|Tuesday|Wednesday|Thursday|Friday)", re.IGNORECASE)

def infer_day_from_path(path: str) -> str:
    m = day_regex.search(path)
    return m.group(1).capitalize() if m else "Unknown"

# --------------------------
# 3) Carga + concatenación (y normalización de nombres de columnas)
# --------------------------
def load_concat_csv(paths):
    dfs = []
    for p in paths:
        if not os.path.exists(p):
            raise FileNotFoundError(f"No existe el CSV: {p}")

        enc = "utf-8"
        if os.path.basename(p) == "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv":
            enc = "cp1252"   # o "latin1"

        print("Leyendo:", p)
        df = pd.read_csv(p, low_memory=False, encoding=enc)

        df.columns = df.columns.str.strip()
        df["Day"] = infer_day_from_path(p)
        df["__source_file"] = os.path.basename(p)
        dfs.append(df)

    return pd.concat(dfs, ignore_index=True)

df_raw = load_concat_csv(csv_paths)
print("Filas totales cargadas:", len(df_raw))
print(df_raw["Day"].value_counts(dropna=False))

# --------------------------
# 4) Reporte de descartes (TCP/UDP + puertos válidos + opcional matched)
# --------------------------
PROTO_COL = "Protocol"
SPORT_COL = "Source Port"
DPORT_COL = "Destination Port"
MATCH_COL = "NewFeat_Matched"
LABEL_COL = "Label"

required = [PROTO_COL, SPORT_COL, DPORT_COL, LABEL_COL]
missing = [c for c in required if c not in df_raw.columns]
if missing:
    raise KeyError(f"Faltan columnas requeridas tras strip(): {missing}")

def discard_report(df, filter_match=False):
    total = len(df)

    m_tcpudp = df[PROTO_COL].isin([6, 17])
    m_ports  = (pd.to_numeric(df[SPORT_COL], errors="coerce") > 0) & (pd.to_numeric(df[DPORT_COL], errors="coerce") > 0)

    report = {}
    report["total_rows"] = total
    report["pct_not_tcpudp"] = 100 * (1 - m_tcpudp.mean())
    report["pct_bad_ports"]  = 100 * (1 - m_ports.mean())

    if filter_match and MATCH_COL in df.columns:
        m_match = df[MATCH_COL].astype(bool)
        report["pct_not_matched"] = 100 * (1 - m_match.mean())
    else:
        report["pct_not_matched"] = None

    mask = m_tcpudp & m_ports
    if filter_match and MATCH_COL in df.columns:
        mask = mask & df[MATCH_COL].astype(bool)

    report["kept_rows"] = int(mask.sum())
    report["kept_pct"]  = 100 * mask.mean()
    return report, mask

rep_no_match, mask_base = discard_report(df_raw, filter_match=False)
print("\n[Descartes] Sin filtrar por NewFeat_Matched:")
for k, v in rep_no_match.items():
    print(f"  {k}: {v}")

rep_with_match, mask_match = discard_report(df_raw, filter_match=True)
print("\n[Descartes] Filtrando además por NewFeat_Matched (si existe):")
for k, v in rep_with_match.items():
    print(f"  {k}: {v}")

FILTER_MATCH = False  # pon True si quieres quedarte solo con matcheables
mask = mask_match if FILTER_MATCH else mask_base
df = df_raw.loc[mask].copy()

print("\nFilas tras filtros:", len(df))
print(df["Day"].value_counts())

# --------------------------
# 5) Tarea: MULTICLASE (tipo de ataque)
# --------------------------
TASK = "multiclass"  # <-- CAMBIO: multiclase

label_clean = df[LABEL_COL].astype(str).str.strip()
y = label_clean  # <-- CAMBIO: se predice la etiqueta completa (BENIGN, DDoS, PortScan, etc.)

# --------------------------
# 6) Split anti-leakage: train Mon-Thu, test Fri
# --------------------------
train_days = {"Monday", "Tuesday", "Wednesday", "Thursday"}
test_days  = {"Friday"}

df_train = df[df["Day"].isin(train_days)].copy()
df_test  = df[df["Day"].isin(test_days)].copy()

if len(df_train) == 0 or len(df_test) == 0:
    raise ValueError(f"Split inválido: train={len(df_train)} test={len(df_test)}. Revisa infer_day_from_path y nombres de archivo.")

y_train = y.loc[df_train.index]
y_test  = y.loc[df_test.index]

print("\nTrain size:", len(df_train), "| Test size:", len(df_test))
print("Train days:", df_train["Day"].value_counts().to_dict())
print("Test days:", df_test["Day"].value_counts().to_dict())

# --------------------------
# 7) Features: eliminar identificadores y posibles fugas
# Quitar puerto mas alto
# --------------------------
DROP_COLS = [
    LABEL_COL,
    "Day",  # <-- CAMBIO 1: NO usar Day como feature
    "Flow ID", "Timestamp",
    "Source IP", "Destination IP",
    "__source_file",
]

# Evitar que el modelo aprenda “calidad de match” si no lo usas como filtro
if MATCH_COL in df_train.columns:
    DROP_COLS.append(MATCH_COL)

X_train = df_train.drop(columns=[c for c in DROP_COLS if c in df_train.columns], errors="ignore")
X_test  = df_test.drop(columns=[c for c in DROP_COLS if c in df_test.columns], errors="ignore")

# --------------------------
# 8) Limpieza + preprocesado dentro del pipeline (Infinity/inf, coerción numérica)
# --------------------------
def clean_dataframe(X: pd.DataFrame) -> pd.DataFrame:
    X = X.copy()

    X.replace(["Infinity", "INF", "-Infinity", "-INF", "inf", "-inf"], np.nan, inplace=True)
    X.replace([np.inf, -np.inf], np.nan, inplace=True)

    # CAMBIO 2: errors="coerce" para robustez (lo raro -> NaN -> imputación)
    for c in X.columns:
        if X[c].dtype == "object":
            X[c] = pd.to_numeric(X[c], errors="coerce")

    return X

cleaner = FunctionTransformer(clean_dataframe, validate=False)

# Columnas por tipo (se determinan en TRAIN tras limpieza)
X_train_clean = clean_dataframe(X_train)
num_cols = X_train_clean.select_dtypes(include=[np.number]).columns.tolist()
cat_cols = [c for c in X_train_clean.columns if c not in num_cols]

numeric_transformer = Pipeline(steps=[
    ("imputer", SimpleImputer(strategy="median")),
])

# No hace falta para arboles
try:
    ohe = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
except TypeError:
    ohe = OneHotEncoder(handle_unknown="ignore", sparse=False)

categorical_transformer = Pipeline(steps=[
    ("imputer", SimpleImputer(strategy="most_frequent")),
    ("onehot", ohe),
])

transformers = [("num", numeric_transformer, num_cols)]
if len(cat_cols) > 0:
    transformers.append(("cat", categorical_transformer, cat_cols))

preprocess = ColumnTransformer(transformers=transformers, remainder="drop")

# --------------------------
# 9) Modelo + búsqueda hiperparámetros (sin mirar test)
# --------------------------
rf = RandomForestClassifier(
    random_state=RANDOM_STATE,
    n_jobs=-1,
    class_weight="balanced"
)

pipe = Pipeline(steps=[
    ("clean", cleaner),
    ("preprocess", preprocess),
    ("model", rf),
])

# Solo uno
param_distributions = {
    "model__n_estimators": [300, 500, 800, 1200],
    "model__max_depth": [None, 10, 20, 30, 50],
    "model__min_samples_split": [2, 5, 10, 20],
    "model__min_samples_leaf": [1, 2, 5, 10],
    "model__max_features": ["sqrt", "log2", None],
    "model__bootstrap": [True, False],
}

groups_train = df_train["Day"].values
n_groups = df_train["Day"].nunique()
if n_groups < 2:
    raise ValueError(f"GroupKFold necesita al menos 2 grupos; encontrados: {n_groups}")

cv = GroupKFold(n_splits=min(4, n_groups))

search = RandomizedSearchCV(
    estimator=pipe,
    param_distributions=param_distributions,
    n_iter=25,
    scoring="f1_macro",  # multiclass -> macro
    cv=cv,
    random_state=RANDOM_STATE,
    n_jobs=-1,
    verbose=1,
    refit=True,
)

search.fit(X_train, y_train, groups=groups_train)
print("\nMejores hiperparámetros:", search.best_params_)
print("Mejor score CV:", search.best_score_)

best_model = search.best_estimator_

# --------------------------
# 10) Evaluación en Friday (test real)
# --------------------------
y_pred = best_model.predict(X_test)

acc = accuracy_score(y_test, y_pred)
f1_macro = f1_score(y_test, y_pred, average="macro")
print("\nTEST Accuracy:", acc)
print("TEST Macro-F1:", f1_macro)

print("\nClassification report:\n", classification_report(y_test, y_pred, digits=4))
print("Confusion matrix:\n", confusion_matrix(y_test, y_pred))

if hasattr(best_model, "predict_proba"):
    proba = best_model.predict_proba(X_test)
    try:
        auc = roc_auc_score(y_test, proba, multi_class="ovr", average="macro")
        print("ROC-AUC:", auc)
    except Exception as e:
        print("ROC-AUC no calculado:", e)

# --------------------------
# 11) Importancia de features
# --------------------------
pre = best_model.named_steps["preprocess"]
feat_names = pre.get_feature_names_out()

rf_fitted = best_model.named_steps["model"]
imp = rf_fitted.feature_importances_
imp_df = pd.DataFrame({"feature": feat_names, "importance": imp}).sort_values("importance", ascending=False)

print("\nTop 25 feature_importances_:\n", imp_df.head(25).to_string(index=False))

# Permutation importance en test (más defendible)
X_test_trans = pre.transform(best_model.named_steps["clean"].transform(X_test))
perm = permutation_importance(
    rf_fitted, X_test_trans, y_test,
    n_repeats=8, random_state=RANDOM_STATE, n_jobs=-1,
    scoring="f1_macro"
)
perm_df = pd.DataFrame({
    "feature": feat_names,
    "perm_importance_mean": perm.importances_mean,
    "perm_importance_std": perm.importances_std
}).sort_values("perm_importance_mean", ascending=False)

print("\nTop 25 permutation importance (test):\n", perm_df.head(25).to_string(index=False))
