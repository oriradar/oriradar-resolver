#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# shellcheck source=/dev/null
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo "OK. Activate with: source backend/.venv/bin/activate"
echo "Run API: uvicorn oritypo_solver.main:app --reload --port 8000"
