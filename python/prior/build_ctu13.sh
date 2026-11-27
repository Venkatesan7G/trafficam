#!/usr/bin/env bash
# Build head C from CTU-13, from scratch, on your own machine. One command:
#
#   python/prior/build_ctu13.sh            # from the repository root
#
# What it does (about 30-60 minutes, 2 GB download, 5 GB disk):
#   1. downloads CTU-13 (CC BY 2.0) into ./data/ctu13 and checks its SHA-256
#   2. unpacks only the labelled flow files (*.binetflow; no pcaps, no malware)
#   3. turns each scenario into head C rows with trafficam's own feature code
#      (go run ./cmd/priorprep), grouped by botnet family
#   4. trains head C with the cross-dataset gate (train on one family, test
#      on the others; refuses to write weights if it does not transfer)
#   5. writes ./data/head_c.tcw and ./data/head_c.tcw.sources.json
#
# Needs: Go 1.24+, Python 3.10+ with numpy and torch (pip install numpy torch),
# curl, tar with bzip2. Re-running skips the download and unpack if done.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
D=${DATA:-data}
URL=https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/CTU-13-Dataset.tar.bz2
SHA=1f8daeca146131a368b432b2d8625de5e4429bce833f3e4cf4bea8312344ab7f   # checked 2026-11-27
mkdir -p "$D/ctu13" "$D/prep"

if [ ! -f "$D/ctu13/CTU-13-Dataset.tar.bz2" ]; then
  echo "1/5 downloading CTU-13 (1.9 GB)"
  curl -fL --retry 3 -o "$D/ctu13/CTU-13-Dataset.tar.bz2.part" "$URL"
  mv "$D/ctu13/CTU-13-Dataset.tar.bz2.part" "$D/ctu13/CTU-13-Dataset.tar.bz2"
fi
echo "   checking SHA-256"
echo "$SHA  $D/ctu13/CTU-13-Dataset.tar.bz2" | sha256sum -c -

if [ ! -f "$D/ctu13/unpacked" ]; then
  echo "2/5 unpacking the labelled flow files only"
  tar -xjf "$D/ctu13/CTU-13-Dataset.tar.bz2" -C "$D/ctu13" --wildcards '*.binetflow'
  touch "$D/ctu13/unpacked"
fi

echo "3/5 computing head C features with trafficam's own code"
# Scenario -> botnet family (from the CTU-13 paper). Each family is one group
# for the cross-dataset gate.
declare -A FAMILY=([1]=neris [2]=neris [9]=neris [3]=rbot [4]=rbot [10]=rbot [11]=rbot
                   [5]=virut [13]=virut [6]=menti [7]=sogou [8]=murlo [12]=nsis)
rm -f "$D"/prep/*.csv
for s in "${!FAMILY[@]}"; do
  go run ./cmd/priorprep -group "${FAMILY[$s]}" -max-normal 20000 -out "$D/prep/${FAMILY[$s]}.csv" \
    "$D"/ctu13/CTU-13-Dataset/"$s"/*.binetflow
done

echo "4/5 training head C (cross-dataset gate)"
SRC=()
for f in "$D"/prep/*.csv; do g=$(basename "$f" .csv); SRC+=(--source "$g,features,$f"); done
python3 -I python/prior/train_prior.py --dataset ctu13 "${SRC[@]}" --out "$D/head_c.tcw" ${MIN_AUC:+--min-auc "$MIN_AUC"}

echo "5/5 done: $D/head_c.tcw and $D/head_c.tcw.sources.json"
echo "Try it (needs the attack-test PR):  go run ./cmd/trafficam attacks -synthetic 14 -train-cap 10s -arms rules,rules+model,rules+model+prior -prior $D/head_c.tcw"
