ifneq ("${wildcard .env}", "")
	include .env
	export
endif

BINARY_NAME=main
DOCKER_COMPOSE=docker compose

.PHONY: help up down build restart test logs tidy fmt lint security check

help: ## Show this help menu
	@echo "Usage: make [command]"
	@echo ""
	@echo "Commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

up: ## Start docker containers in the background
	$(DOCKER_COMPOSE) up -d

down: ## Stop and remove docker containers
	$(DOCKER_COMPOSE) down

build: ## Rebuild images and start docker containers
	$(DOCKER_COMPOSE) up -d --build

restart: ## Restart docker containers (down + up)
	$(DOCKER_COMPOSE) down
	$(DOCKER_COMPOSE) up -d

test: ## Run unit tests with data race detection
	go test -v -race ./...

logs: ## View and follow docker container logs
	$(DOCKER_COMPOSE) logs -f

tidy: ## Clean up and verify go.mod dependencies
	go mod tidy
	go mod verify

fmt: ## Format Go code according to official standards
	go fmt ./...

lint: ## Run advanced static analysis using golangci-lint (includes go vet)
	golangci-lint run

security: ## Check for known vulnerabilities in code and dependencies
	go install golang.org/x/exp/cmd/govulncheck@latest
	govulncheck ./...

check: fmt tidy security test ## Run all verification checks before pushing code
	@echo "Pre-push checks passed!"

setup: ## Create local .env file and download dependencies
	@if [ ! -f .env ]; then cp .env.example .env && echo ".env file created"; fi
	go mod download