#!/usr/bin/env bash
# trafficam VM lab, Linux: run attack-SHAPED traffic and write a labels file.
#
# Nothing here is malware. Each scenario makes the same kind of network
# traffic as a real attack (calling home, uploading data, random DNS names,
# a port scan), aimed at the sink VM you control (sink.py). Run it ONLY in a
# lab VM, and point SINK and SCAN_NET at your own lab network.
#
#   SINK=192.168.56.20 ./plant.sh all          # every scenario, one after another
#   SINK=192.168.56.20 ./plant.sh beacon exfil # just these
#
# Scenarios: beacon exfil dga dns-tunnel scan dropper
# Labels are appended to $LABELS (default ./labels.jsonl). Then, on the VM:
#   sudo trafficam attacks -data /var/lib/trafficam -labels labels.jsonl
#
# Settings (environment variables):
#   SINK          IP of the sink VM (required)
#   SCAN_NET      first three parts of the network to scan (default: SINK's /24)
#   BEACON_MIN    beacon length in minutes (default 120)
#   EXFIL_MB      upload size (default 300)
#   TUNNEL_DOMAIN domain for DNS-tunnel names (default example.com; queries go
#                 to your DNS resolver and that domain's servers, carrying no data)
set -euo pipefail
: "${SINK:?set SINK to the IP of the sink VM}"
SCAN_NET=${SCAN_NET:-${SINK%.*}}
BEACON_MIN=${BEACON_MIN:-120}
EXFIL_MB=${EXFIL_MB:-300}
TUNNEL_DOMAIN=${TUNNEL_DOMAIN:-example.com}
LABELS=${LABELS:-labels.jsonl}
PY=${PY:-python3}

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
label() { # id kind program host start what
  printf '{"id":"%s","kind":"%s","program":"%s","host":"%s","start":"%s","end":"%s","what":"%s"}\n' \
    "$1" "$2" "$3" "$4" "$5" "$(now)" "$6" >> "$LABELS"
  echo "  done: $1 (label written to $LABELS)"
}

beacon() {
  local s; s=$(now); echo "beacon: python3 calls http://$SINK:8080 every ~60 s for $BEACON_MIN min"
  "$PY" - "$SINK" "$BEACON_MIN" <<'PYEOF'
import random, sys, time, urllib.request
sink, mins = sys.argv[1], int(sys.argv[2])
end = time.time() + mins * 60
while time.time() < end:
    try: urllib.request.urlopen(f"http://{sink}:8080/ping?id={random.randint(1, 1 << 30)}", timeout=5).read()
    except Exception: pass
    time.sleep(55 + random.random() * 10)
PYEOF
  label beacon beacon python "$SINK" "$s" "interpreter beacons to the sink every ~60 s"
}

exfil() {
  local s; s=$(now); echo "exfil: python3 uploads $EXFIL_MB MB to http://$SINK:8443"
  "$PY" - "$SINK" "$EXFIL_MB" <<'PYEOF'
import os, sys, http.client
sink, mb = sys.argv[1], int(sys.argv[2])
for _ in range(mb // 50 or 1):
    c = http.client.HTTPConnection(sink, 8443, timeout=60)
    c.request("POST", "/upload", body=os.urandom(50 << 20))
    c.getresponse().read(); c.close()
PYEOF
  label exfil exfil python "$SINK" "$s" "interpreter uploads ${EXFIL_MB} MB to the sink"
}

dga() {
  local s; s=$(now); echo "dga: python3 looks up 200 random .com names, then calls the sink"
  "$PY" - "$SINK" <<'PYEOF'
import random, socket, string, sys, time, urllib.request
for _ in range(200):
    n = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(random.randint(12, 20))) + ".com"
    try: socket.getaddrinfo(n, 443)
    except Exception: pass
    time.sleep(0.3)
try: urllib.request.urlopen(f"http://{sys.argv[1]}:8080/hello", timeout=5).read()
except Exception: pass
PYEOF
  label dga dga python "" "$s" "200 random-looking lookups, then a call home"
}

dns_tunnel() {
  local s; s=$(now); echo "dns-tunnel: python3 sends 1000 long random names under $TUNNEL_DOMAIN"
  "$PY" - "$TUNNEL_DOMAIN" <<'PYEOF'
import base64, os, socket, sys, time
for _ in range(1000):
    n = base64.b32encode(os.urandom(30)).decode().rstrip("=").lower() + "." + sys.argv[1]
    try: socket.getaddrinfo(n, 53)
    except Exception: pass
    time.sleep(0.2)
PYEOF
  label dns-tunnel dns-tunnel python "$TUNNEL_DOMAIN" "$s" "1000 long encoded DNS names under one domain"
}

scan() {
  local s; s=$(now); echo "scan: python3 tries $SCAN_NET.1-254 on ports 22, 445, 3389"
  "$PY" - "$SCAN_NET" <<'PYEOF'
import socket, sys
for i in range(1, 255):
    for p in (22, 445, 3389):
        so = socket.socket(); so.settimeout(0.3)
        try: so.connect((f"{sys.argv[1]}.{i}", p))
        except Exception: pass
        finally: so.close()
PYEOF
  label scan scan python "$SCAN_NET." "$s" "TCP connect scan of the lab /24"
}

dropper() {
  local s d; s=$(now); d=$(mktemp -d /tmp/.cache-XXXX)
  cp "$(command -v curl)" "$d/svchelper"
  echo "dropper: a copy of curl named svchelper in $d calls the sink every 3 min for 30 min"
  for _ in $(seq 10); do "$d/svchelper" -s -o /dev/null "http://$SINK:8080/check" || true; sleep 180; done
  rm -rf "$d"
  label dropper new-program svchelper "$SINK" "$s" "new program in a temp folder calls home"
}

run() {
  case "$1" in
    beacon) beacon ;; exfil) exfil ;; dga) dga ;; dns-tunnel) dns_tunnel ;; scan) scan ;; dropper) dropper ;;
    all) for x in beacon exfil dga dns-tunnel scan dropper; do run "$x"; sleep 600; done ;;
    *) echo "unknown scenario $1"; exit 2 ;;
  esac
}
[ $# -gt 0 ] || { sed -n '2,25p' "$0"; exit 2; }
for x in "$@"; do run "$x"; done
