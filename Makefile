# Thot Secure — Makefile de développement
# Cible principale : rends le projet utilisable en local en une commande (`make dev`).
# Toutes les cibles fonctionnent sous Linux/macOS. Sous Windows, voir scripts/dev-setup.ps1.

SHELL := /bin/bash
PY ?= python3
VENV ?= .venv
BIN := $(VENV)/bin
THOT := PYTHONPATH=src $(PY) -m thotsecure.cli
TENANT ?= demo
HOST ?= 127.0.0.1
PORT ?= 8080

.DEFAULT_GOAL := help
.PHONY: help venv install install-offline dev init-db demo seed serve test test-api test-engine lint fmt typecheck rules policies validate doctor audit-verify clean dist sbom sign compose-up compose-down ps docker-build tree security-check

help: ## Affiche cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

venv: ## Crée l'environnement virtuel
	$(PY) -m venv $(VENV)
	$(BIN)/python -m pip install --upgrade pip

install: venv ## Installe le paquet en mode éditable avec les outils de dev
	$(BIN)/python -m pip install -e ".[dev]"

install-offline: venv ## Installation sans réseau (dépendances déjà présentes)
	$(BIN)/python -m pip install -e . --no-deps
	@echo "==> Installation hors ligne : seules les dépendances déjà présentes sont utilisées."

dev: install init-db ## Prépare un environnement de développement complet
	@echo "==> Prêt. Lance 'make serve' puis 'make demo' dans un autre terminal."

init-db: ## Initialise la base de données locale
	$(THOT) init-db

demo: ## Crée le tenant de démonstration, injecte des événements et montre findings + actions
	$(THOT) demo --tenant $(TENANT)

seed: ## Alias de demo
	$(THOT) demo --tenant $(TENANT)

serve: ## Lance le serveur de développement (dry-run actif par défaut)
	THOT_DRY_RUN=true THOT_AUTONOMY=supervised PYTHONPATH=src \
		$(PY) -m uvicorn thotsecure.main:app --host $(HOST) --port $(PORT) --reload

test: ## Lance toute la suite de tests (unittest stdlib, sans dépendance externe)
	PYTHONPATH=src $(PY) -m unittest discover -s tests -t . -v

test-api: ## Tests de l'API uniquement
	PYTHONPATH=src $(PY) -m unittest discover -s tests -t . -p "test_api.py" -v

test-engine: ## Tests du moteur (règles, scoring, décision, actions, audit)
	PYTHONPATH=src $(PY) -m unittest discover -s tests -t . -p "test_*.py" -v -k engine

lint: ## Analyse statique (ruff)
	$(BIN)/ruff check src tests

fmt: ## Formatage automatique
	$(BIN)/ruff format src tests
	$(BIN)/ruff check --fix src tests

typecheck: ## Vérification de types (mypy, non bloquant)
	$(BIN)/mypy src/thotsecure || true

rules: ## Valide la bibliothèque de règles de détection
	$(THOT) rules validate --path rules

policies: ## Valide les politiques de décision
	$(THOT) policies validate --path policies

validate: rules policies ## Valide règles + politiques

doctor: ## Auto-diagnostic de l'installation et des défauts de sûreté
	$(THOT) doctor

audit-verify: ## Vérifie l'intégrité de la chaîne d'audit (code de sortie 3 si corrompue)
	$(THOT) audit verify --tenant $(TENANT)

clean: ## Nettoie les artefacts de build et caches
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

dist: ## Construit les distributions Python (sdist + wheel)
	$(PY) -m build

sbom: ## Génère un SBOM CycloneDX (nécessite syft)
	syft dir:. -o cyclonedx-json=thotsecure-sbom.cdx.json

sign: ## Signe les artefacts avec Sigstore cosign (keyless)
	cosign sign-blob --yes thotsecure-sbom.cdx.json --output-signature thotsecure-sbom.cdx.json.sig

compose-up: ## Démarre la pile Docker Compose (dry-run actif)
	docker compose up -d --build
	@echo "==> Console : http://localhost:8080/  (mot de passe : THOT_BOOTSTRAP_API_KEY)"

compose-down: ## Arrête la pile Docker Compose
	docker compose down

ps: ## État des conteneurs
	docker compose ps

docker-build: ## Construit l'image locale
	docker build -t thotsecure:dev .

security-check: ## Contrôles de sûreté du dépôt (secrets, TODO de sécurité, dry-run par défaut)
	@echo "==> Recherche de secrets évidents…"
	@grep -rInE "(api[_-]?key|secret|password|token)[[:space:]]*[:=][[:space:]]*[\"'][A-Za-z0-9_\-]{16,}" src config || echo "    aucun secret en dur détecté"
	@echo "==> Vérification des défauts sûrs…"
	@grep -rn "dry_run" src/thotsecure/core/config.py | head -5
	@echo "==> Vérification de l'absence de capacités offensives…"
	@grep -rInE "(exploit|payload|shellcode|reverse_shell|dos_attack)" src/thotsecure || echo "    aucune capacité offensive détectée"

tree: ## Affiche l'arborescence du projet
	find . -maxdepth 2 -not -path './.git*' -not -path './.venv*' -not -path './node_modules*' | sort | head -80
