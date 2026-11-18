#!/usr/bin/env bash
set -u
mkdir -p /logs/verifier
score=0
write_reward() { printf '%.4f\n' "$score" > /logs/verifier/reward.txt; }
trap write_reward EXIT

if pytest -q /tests/test_outputs.py; then
  score=1
fi
