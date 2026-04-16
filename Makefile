GO ?= /usr/local/go/bin/go
PKG := github.com/oscar/gossh
BIN_DIR := bin
LDFLAGS := -s -w

.PHONY: all build build-server build-client build-keygen test test-short test-interop fmt vet lint clean tidy

all: build test

build: build-server build-client build-keygen

build-server:
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/gosshd ./cmd/gosshd

build-client:
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/gossh ./cmd/gossh

build-keygen:
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/gossh-keygen ./cmd/gossh-keygen

test:
	$(GO) test -race -timeout 120s ./...

test-short:
	$(GO) test -short -timeout 30s ./...

test-interop:
	$(GO) test -race -tags=interop -timeout 300s ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BIN_DIR) coverage.out coverage.html

coverage:
	$(GO) test -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
