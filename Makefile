.PHONY: build test vet clean run up down env

MODULE = github.com/thieuson1984/traefik-hermes-guard
GO ?= go

env:
	@if [ ! -f .env ]; then \
		echo "[ENV] Creating .env from .env.example..."; \
		cp .env.example .env; \
		echo "Edit .env with your Hermes Agent IP and tokens."; \
	else \
		echo "[ENV] .env already exists."; \
	fi

build: vet test
	@echo "[BUILD] Compiling plugin..."
	$(GO) build -o /dev/null ./...

test:
	@echo "[TEST] Running tests..."
	$(GO) test -v -race -count=1 ./...

vet:
	@echo "[VET] Running go vet..."
	$(GO) vet ./...

clean:
	@echo "[CLEAN] Remove artifacts..."
	rm -f traefik-hermes-guard

up:
	@echo "[DOCKER] Starting services..."
	docker compose up -d

down:
	@echo "[DOCKER] Stopping services..."
	docker compose down

logs:
	docker compose logs -f

restart: down up

redis-cli:
	docker compose exec redis redis-cli

test-traefik:
	@echo "Testing Traefik API..."
	curl -s http://localhost:8080/api/rawdata | head -100

test-whoami:
	@echo "Normal request..."
	curl -v http://whoami.localhost/
	@echo ""
	@echo "SQLi request..."
	curl -v "http://whoami.localhost/?id=1%20UNION%20SELECT%20password%20FROM%20users"

test-xss:
	@echo "XSS request..."
	curl -v "http://whoami.localhost/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
