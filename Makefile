# IaCGuard

SHELL := /bin/bash
VENV  := .venv
PY    := $(VENV)/bin/python
PIP   := $(VENV)/bin/pip
TF    := terraform -chdir=infra

.PHONY: help install run deploy test load-test metrics docs destroy clean

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

destroy: ## Remove all AWS resources
	$(TF) destroy -auto-approve

clean: ## Remove local build artefacts
	rm -rf build $(VENV) .pytest_cache
