# IaCGuard

SHELL := /bin/bash
VENV  := .venv
PY    := $(VENV)/bin/python
PIP   := $(VENV)/bin/pip
TF    := terraform -chdir=infra

# The deck generator needs the pptx skill's theme helper and a metrics file.
PPTX_SKILL   ?= $(HOME)/.claude/skills/synced/62a18d42-c829-4249-8859-f58a9e2ad134_698cf43b-a118-4081-b0e5-b5a8b7f6790e/pptx
METRICS_JSON ?= build/metrics.json

.PHONY: help install run deploy test load-test metrics docs screens deck destroy clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[1m%-12s\033[0m %s\n", $$1, $$2}'

install: $(VENV)/.stamp ## Set up the local virtualenv
$(VENV)/.stamp: requirements.txt
	python3 -m venv $(VENV)
	$(PIP) install --quiet --upgrade pip
	$(PIP) install --quiet -r requirements.txt pytest
	@touch $@

run: install ## Run the app
	@$(PY) app.py

deploy: install ## Build and deploy everything to AWS
	./scripts/build_lambda.sh
	$(TF) init -upgrade -input=false
	$(TF) apply -auto-approve
	@# Piped rather than redirected: terraform 1.16 writes nothing when its
	@# stdout is a regular file, so `output -json > file` silently gives 0 bytes.
	@$(TF) output -json cli_config | python3 -c \
	  "import json,sys; d=json.load(sys.stdin); json.dump(d, open('.iacguard.json','w'), indent=2); print('\nwrote .iacguard.json'); print(json.dumps(d, indent=2))"

test: install ## Run the rule tests (no AWS needed)
	$(VENV)/bin/pytest tests -q

load-test: ## Fire 20 concurrent scans to demonstrate scaling
	./scripts/load_test.sh 20

metrics: ## Print the CloudWatch metrics for the last hour
	./scripts/metrics.sh

docs: install ## Regenerate the PDF guides
	$(PIP) install --quiet -r docs/requirements.txt
	$(PY) scripts/md_to_pdf.py docs/DEMO_AND_SCREENSHOTS.md docs/IaCGuard-Demo-and-Screenshot-Guide.pdf
	$(PY) scripts/md_to_pdf.py docs/SLIDE_CONTENT.md docs/IaCGuard-Slide-Content.pdf

screens: install ## Re-capture the terminal screenshots from real runs
	$(PY) scripts/capture_screens.py

deck: install ## Rebuild the submission deck (needs the local-only generator)
	@test -f scripts/build_deck.js || { \
	  echo "scripts/build_deck.js is not in this repository."; \
	  echo "It holds presentation content rather than project code and is"; \
	  echo "kept locally. Nothing else here depends on it."; exit 1; }
	@test -d node_modules || npm install --no-fund --no-audit pptxgenjs
	PPTX_SKILL="$(PPTX_SKILL)" NODE_PATH="$(PWD)/node_modules" \
	  METRICS_JSON="$(METRICS_JSON)" node scripts/build_deck.js

destroy: ## Remove all AWS resources
	$(TF) destroy -auto-approve

clean: ## Remove local build artefacts
	rm -rf build $(VENV) .pytest_cache
