ifneq ("${wildcard .env}", "")
	include .env
	export
endif

BINARY_NAME=main
DOCKER_COMPOSE=docker compose

.PHONY: help up down build restart test logs tidy fmt lint security check

help:
	@echo "Usage: make [command]"
	@echo ""
	@echo "Commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}''

up:
	$(DOCKER_COMPOSE) up -d

down:
	$(DOCKER_COMPOSE) down

build:
	$(DOCKER_COMPOSE) up -d --build

restart: down up

test:
	go test -v -race ./...

logs:
	$(DOCKER_COMPOSE) logs -f

tidy:
	go mod tidy
	go mod verify

fmt:
	go fmt./...

lint:
	golangci-lint run

security:
	go install golang.org/x/exp/cmd/govulncheck@latest
	govulncheck ./...

check: fmt tidy security test
	@echo "Pre-push checks passed!"

setup: 
	@if [ ! -f .env ]; then cp .env.example && echo ".env file created"; fi
	go mod download