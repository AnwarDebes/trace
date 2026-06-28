# TRACE: Tsetlin Runtime Assurance & Certification Engine
# (Windows users without `make`: run the python commands shown in each rule.)

PY ?= python

.PHONY: help install test data reproduce quick figures paper demo clean

help:
	@echo "make install    - editable install + experiment/dev extras"
	@echo "make test       - run the unit test suite (pytest)"
	@echo "make data       - download + cache the real datasets"
	@echo "make reproduce  - run every experiment, regenerate results/*.json"
	@echo "make quick      - fast 3-seed smoke of all experiments"
	@echo "make figures    - rebuild paper/figures/*.pdf from results/*.json"
	@echo "make paper      - compile paper/trace.pdf"
	@echo "make demo       - run the quickstart demo"

install:
	$(PY) -m pip install -e ".[experiments,data,dev]"

test:
	$(PY) -m pytest -q

data:
	$(PY) scripts/fetch_data.py

reproduce: data
	$(PY) -u experiments/run_all.py

quick: data
	$(PY) -u experiments/run_all.py --quick

figures:
	$(PY) scripts/make_figures.py

paper: figures
	cd paper && pdflatex -interaction=nonstopmode trace.tex && bibtex trace && pdflatex -interaction=nonstopmode trace.tex && pdflatex -interaction=nonstopmode trace.tex

demo:
	$(PY) demo/quickstart.py

clean:
	$(PY) -c "import shutil,glob,os; [shutil.rmtree(p,ignore_errors=True) for p in glob.glob('**/__pycache__',recursive=True)]"
	cd paper && $(PY) -c "import glob,os; [os.remove(f) for e in ('aux','log','out','bbl','blg','toc') for f in glob.glob('*.'+e)]"
