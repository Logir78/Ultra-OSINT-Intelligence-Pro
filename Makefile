# NOCTUA.osint — developer shortcuts
.DEFAULT_GOAL := help
.PHONY: help up down logs build backend frontend install test lint format clean

help: ## Muestra esta ayuda
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

up: ## Levanta todo el stack con Docker (Mongo + backend + frontend)
	docker compose up --build

down: ## Detiene el stack
	docker compose down

logs: ## Muestra los logs del stack
	docker compose logs -f

build: ## Construye las imágenes Docker
	docker compose build

backend: ## Arranca el backend en local (requiere venv y Mongo)
	cd backend && uvicorn server:app --reload --port 8001

frontend: ## Arranca el frontend en local
	cd frontend && yarn start

install: ## Instala dependencias de backend (dev) y frontend
	cd backend && pip install -r requirements.txt -r requirements-dev.txt
	cd frontend && yarn install

test: ## Ejecuta los tests del backend
	cd backend && pytest

lint: ## Linting y comprobación de tipos (backend)
	cd backend && ruff check . && black --check . && mypy . || true

format: ## Formatea el código (backend)
	cd backend && black . && ruff check --fix .

clean: ## Limpia cachés de Python
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
