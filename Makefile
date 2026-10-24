PY := .venv/bin/python
UV := uv

.PHONY: setup env test ingest ws12 w10 cross check clean-cache

setup:
	$(UV) venv --python 3.12 .venv
	$(UV) pip install --python $(PY) -r requirements.txt

env:
	$(PY) scripts/check_env.py

test:
	$(PY) -m pytest tests/ -q

ingest:
	bash scripts/ingest_all.sh

ws12:
	$(PY) -m src.experiment --train WS12 --test WS12

w10:
	$(PY) -m src.experiment --train W10 --test W10

ubuntu:
	bash scripts/ingest_ubuntu.sh

cross:
	$(PY) -m src.experiment --train W10 --test WS12
	$(PY) -m src.experiment --train WS12 --test W10

check:
	$(PY) scripts/check_leakage.py experiments/results/cache

clean-cache:
	rm -rf experiments/results/cache
