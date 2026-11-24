import os
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from imblearn.over_sampling import RandomOverSampler

BASE_DIR = "/shared-hdd/TFGRManzaneque/resultados"
csv_path = os.path.join(BASE_DIR, "dataset_final_cics_2017.csv")

df = pd.read_csv(csv_path)

# Me quedo solo con el puerto correspondiente al servicio
df["Source Port"] = df["Source Port"].fillna(-1)
df["Destination Port"] = df["Destination Port"].fillna(-1)

df["Service port"] = df[["Source Port", "Destination Port"]].min(axis=1).astype("float64")

print("Formato flujos csv:", df.shape)
print(df.head(5))
print("Info columnas:")
df.info()

# Chequeos
print("\nNulos:")
print(df.isna().sum().sort_values(ascending=False).head(20))

print("\nDistribucion etiquetas:")
print(df["Label"].value_counts(dropna=False).head(20))

# Establezco la etiqueta como target
y = df["Label"].astype(str)

# Caracteristicas a dropear
drop_cols = ["Label", "Flow ID", "Source IP", "Destination IP", "Timestamp", "Source Port", "Destination Port", "Init_Win_bytes_backward", "Init_Win_bytes_forward"]

#X = df.drop(columns=[c for c in drop_cols if c in df.columns])

X = df

# Quitar nulls de flow/bytes y meter la mediana. Mejor borrar?
X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(X.median(numeric_only=True))
X_flow_id = X["Flow ID"].unique()

# Divido dataset en entrenamiento y test
X_flowID_train, X_flowID_test = train_test_split(
    X_flow_id,# y,
    test_size=0.25,
    random_state=42,
    # stratify=y
)
print(len(X_flowID_train), len(X_flowID_test))

X_train = X[X["Flow ID"].isin(X_flowID_train)]
X_test = X[X["Flow ID"].isin(X_flowID_test)]

y_train = y[(X["Flow ID"].isin(X_flowID_train))]
y_test = y[(X["Flow ID"].isin(X_flowID_test))]

print(X_train.shape, X_test.shape, y_train.shape, y_test.shape)
X_train = X_train.drop(columns=[c for c in drop_cols if c in df.columns])
X_test = X_test.drop(columns=[c for c in drop_cols if c in df.columns])

rf = RandomForestClassifier(
    n_estimators=400,
    random_state=42,
    n_jobs=-1,
    max_depth=None,
    min_samples_leaf=2,
    min_samples_split=10,
    max_features="sqrt",
    class_weight="balanced_subsample",
    oob_score=True
)
rf.fit(X_train, y_train)

# Evaluación
y_pred = rf.predict(X_test)

print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# Feature importance
importances = pd.Series(rf.feature_importances_, index=X_train.columns).sort_values(ascending=False)
print("\nFeature importance:\n", importances.head(20))
