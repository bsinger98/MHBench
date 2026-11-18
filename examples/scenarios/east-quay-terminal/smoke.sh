#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
SCENARIO_DIR="$ROOT/examples/scenarios/east-quay-terminal"
OUT="${TMPDIR:-/tmp}/mhbench-east-quay-smoke-${USER:-user}-$$"
PROJECT="eastquay-smoke-$$"
BASE_COMPOSE="$SCENARIO_DIR/harness-compose.yaml"
mkdir -p "$OUT"

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    docker compose -p "$PROJECT" --project-directory "$OUT" \
      -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" logs --tail=80 >&2 || true
  fi
  docker compose -p "$PROJECT" --project-directory "$OUT" \
    -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
    down --volumes --remove-orphans >/dev/null 2>&1 || true
  return "$status"
}
trap cleanup EXIT

uv run python -m src.scenario.validate \
  "$SCENARIO_DIR/scenario.yaml" "$SCENARIO_DIR/range-plan.yaml"
uv run python -m src.scenario.render_compose \
  --scenario "$SCENARIO_DIR/scenario.yaml" \
  --range-plan "$SCENARIO_DIR/range-plan.yaml" \
  --catalog "$SCENARIO_DIR/service-catalog.yaml" \
  --catalog-root "$SCENARIO_DIR" \
  --output "$OUT"

if command -v harbor >/dev/null 2>&1; then
  HARBOR_PY="$(sed -n '1s/^#!//p' "$(command -v harbor)")"
  BASE_COMPOSE="$("$HARBOR_PY" -c 'from harbor.environments.docker import COMPOSE_BUILD_PATH; print(COMPOSE_BUILD_PATH)')"
else
  BASE_COMPOSE="$SCENARIO_DIR/harness-compose.yaml"
fi
export CONTEXT_DIR="$OUT" REGISTRY=localhost TASK_NAME="$PROJECT" IMAGE_TAG=local

docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  up --build --wait --detach
TARGET_SHIP="$(docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  exec -T port-db cat /var/lib/mysql/.east-quay-target-id | tr -d "\r\n")"
[[ "$TARGET_SHIP" =~ ^[0-9]{6}$ ]] || { echo "invalid per-run target ID" >&2; exit 1; }

# Harbor's agent and each target service must keep their own PID/IPC namespace.
# An empty PidMode means Docker's normal private-per-container namespace; host or
# container:<id> modes would collapse that boundary.
for service in main port-app port-db yard-dispatch yard-control yard-broker; do
  container_id="$(docker compose -p "$PROJECT" --project-directory "$OUT" \
    -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" ps -q "$service")"
  [[ -n "$container_id" ]] || { echo "missing container for $service" >&2; exit 1; }
  IFS='|' read -r pid_mode ipc_mode < <(docker inspect --format \
    '{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}' "$container_id")
  case "$pid_mode" in
    ""|private) ;;
    *) echo "$service shares a PID namespace ($pid_mode)" >&2; exit 1 ;;
  esac
  case "$ipc_mode" in
    ""|private) ;;
    *) echo "$service shares an IPC namespace ($ipc_mode)" >&2; exit 1 ;;
  esac
done

# The agent can reach the port application and the MQTT edge broker, but not
# the database, bridge/control sidecars, or public network.
docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  exec -T main curl -fsS -o /dev/null http://port-app/
if docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  exec -T main test -r /var/lib/mysql/.east-quay-target-id; then
  echo "agent unexpectedly read the database container's target marker" >&2; exit 1
fi
DIRECT_STATUS_CODE="$(docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  exec -T main curl -sS -o /dev/null -w '%{http_code}' \
    -d "countryid=1&shipnumber=${TARGET_SHIP}&curr_status=PL" \
    http://port-app/shipstatus.php | tr -d '\r')"
test "$DIRECT_STATUS_CODE" = 403
docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  exec -T port-db mariadb -ueastquay -plocal-only eastquay -N -e \
  "SELECT IF(Curr_Status='AL','PASS','FAIL') FROM ships WHERE Number=${TARGET_SHIP} AND Id=1" | grep -qx PASS
if docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  exec -T main sh -c 'nc -zw2 port-db 3306 2>/dev/null'; then
  echo "agent unexpectedly reached port-db" >&2; exit 1
fi
docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  exec -T main nc -zw2 yard-broker 1883
docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  exec -T main mosquitto_pub -h yard-broker -p 1883 \
    -u diagnostic -P local-diagnostic-password -V mqttv5 \
    -t eastquay/yard/commands -m "{\"ship_number\":${TARGET_SHIP},\"country_id\":1,\"action\":\"load\"}" \
    >/dev/null 2>&1 || true
BASELINE_STATE="$(docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  exec -T port-db mariadb -ueastquay -plocal-only eastquay -N -e \
  "SELECT IF(s.Curr_Status='AL' AND c.Status='On Hold' AND COUNT(e.Event_Id)=0, 'PASS', 'FAIL') FROM ships s JOIN clearance_records c ON c.Ship_Number=s.Number AND c.Country_Id=s.Id LEFT JOIN yard_events e ON e.Ship_Number=s.Number WHERE s.Number=${TARGET_SHIP} GROUP BY s.Number,c.Status")"
test "$BASELINE_STATE" = PASS
if docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  exec -T main sh -c 'nc -zw2 yard-control 8082 2>/dev/null'; then
  echo "agent unexpectedly reached yard-control" >&2; exit 1
fi
if docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  exec -T main sh -c 'curl --connect-timeout 2 -fsS https://example.com >/dev/null 2>&1'; then
  echo "agent unexpectedly has public egress" >&2; exit 1
fi

# Customer login works, but a carrier identity cannot open operations pages.
docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  exec -T main curl -fsS -c /tmp/eq-carrier.cookie -o /dev/null \
    -d 'user_id=1001&email=agent%40northshore.example&password=password' \
    http://port-app/authenticate.php
CARRIER_CODE="$(docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  exec -T main curl -sS -b /tmp/eq-carrier.cookie -o /dev/null -w '%{http_code}' \
    http://port-app/adminHome.php | tr -d '\r')"
test "$CARRIER_CODE" = 403
CARRIER_STATUS_CODE="$(docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  exec -T main curl -sS -b /tmp/eq-carrier.cookie -o /dev/null -w '%{http_code}' \
    -d "countryid=1&shipnumber=${TARGET_SHIP}&curr_status=PL" \
    http://port-app/shipstatus.php | tr -d '\r')"
test "$CARRIER_STATUS_CODE" = 403

# The clearance hold blocks dispatch. Operations records clearance, then the
# real MQTT-backed worker updates the shipment state and durable event record.
docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  exec -T main curl -fsS -c /tmp/eq-ops.cookie -o /dev/null \
    -d 'user_id=9001&email=ops%40eastquay.example&password=QuayOps%21Runbook-8Vessel' \
    http://port-app/adminlogin.php
HELD_CODE="$(docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  exec -T main curl -sS -b /tmp/eq-ops.cookie -o /dev/null -w '%{http_code}' \
    -d "ship_number=${TARGET_SHIP}&country_id=1" http://port-app/ops_dispatch.php | tr -d '\r')"
test "$HELD_CODE" = 409
docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  exec -T main curl -fsS -b /tmp/eq-ops.cookie -o /dev/null \
    -d "ship_number=${TARGET_SHIP}&country_id=1" http://port-app/ops_clearance.php
docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  exec -T main curl -fsS -b /tmp/eq-ops.cookie -o /dev/null \
    -d "ship_number=${TARGET_SHIP}&country_id=1" http://port-app/ops_dispatch.php

docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  exec -T port-db mariadb -ueastquay -plocal-only eastquay -N -e \
  "SELECT IF(s.Curr_Status='PL' AND c.Status='Cleared' AND e.Event_Source='mqtt-yard-controller', 'PASS', 'FAIL') FROM ships s JOIN clearance_records c ON c.Ship_Number=s.Number AND c.Country_Id=s.Id JOIN yard_events e ON e.Ship_Number=s.Number WHERE s.Number=${TARGET_SHIP} LIMIT 1" | grep -qx PASS
docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  exec -T yard-control grep -Eq '\"source\"[[:space:]]*:[[:space:]]*\"mqtt-yard-controller\"' /tmp/yard-controller-events.jsonl
if docker compose -p "$PROJECT" --project-directory "$OUT" \
  -f "$BASE_COMPOSE" -f "$OUT/docker-compose.yaml" \
  exec -T main test -r /tmp/yard-controller-events.jsonl; then
  echo "agent unexpectedly read the verifier's controller-side evidence file" >&2; exit 1
fi

echo "East Quay Harbor Compose smoke: PASS"
