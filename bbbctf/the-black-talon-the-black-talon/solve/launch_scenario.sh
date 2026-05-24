#!/bin/sh
# Inside the docker container.
# Args: <channel> <protagonist_name> <sheriff_name> <secret>
set -e
CHAN="${1:-saloon}"
PROT="${2:-vulture}"
SHERIFF="${3:-sheriff}"
SECRET="${4:-testtestabcdefghABCDEFGH01234567testtestabcdefghABCDEFGH01234567}"
N="${5:-50}"

echo "[launch] starting $N bots on channel=$CHAN"
/bin/talon/client --server 127.0.0.1 --port 31337 --channel "$CHAN" --multiple-clients "$N" &
BOTS_PID=$!
sleep 3
echo "[launch] waiting for protagonist '$PROT' to join $CHAN..."
# Wait until protagonist is in channel by checking via a probe client.
# Just poll for ~30s
for i in $(seq 1 60); do
    R=$(printf 'CONNECT __probe%d__\nPEEK %s\nGOODBYE\n' "$i" "$CHAN" | nc -q 1 127.0.0.1 31337 2>/dev/null || true)
    if echo "$R" | grep -q " $PROT"; then
        echo "[launch] $PROT seen in $CHAN"
        break
    fi
    sleep 0.5
done

echo "[launch] starting sheriff $SHERIFF with secret length=${#SECRET}"
/bin/talon/client --server 127.0.0.1 --port 31337 --channel "$CHAN" \
    --force-user "$PROT" --username "$SHERIFF" --secret "$SECRET" -ev &
SHERIFF_PID=$!

echo "[launch] all running. bots=$BOTS_PID sheriff=$SHERIFF_PID"
wait $BOTS_PID
