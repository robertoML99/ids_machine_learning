#!/usr/bin/env bash
set -o pipefail

BASE_DIR="/shared-hdd/TFGRManzaneque"
CODE_DIR="${BASE_DIR}/codigo"

echo "=========LUNES==========="
python3 "${CODE_DIR}/lunes_V2.py"
echo "=========MARTES==========="
python3 "${CODE_DIR}/martes_V2.py"
echo "=========MIERCOLES==========="
python3 "${CODE_DIR}/miercoles_V2.py"
echo "=========JUEVES==========="
python3 "${CODE_DIR}/jueves_V2.py"
echo "=========VIERNES==========="
python3 "${CODE_DIR}/viernes_V2.py"
echo "=========FUSIONANDO CSVs==========="
python3 "${CODE_DIR}/fusionar_dataset_cics_2017.py"