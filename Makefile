GO ?= /usr/local/go/bin/go
PKG := github.com/oreparaz/gossh
BIN_DIR := bin
LDFLAGS := -s -w

.PHONY: all build build-server build-client build-keygen build-scp test test-short test-interop e2e fmt vet lint clean tidy coverage

all: build test

build: build-server build-client build-keygen build-scp

build-server:
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/gosshd ./cmd/gosshd

build-client:
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/gossh ./cmd/gossh

build-keygen:
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/gossh-keygen ./cmd/gossh-keygen

build-scp:
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/gossh-scp ./cmd/gossh-scp

test:
	$(GO) test -race -timeout 180s ./...

test-short:
	$(GO) test -short -timeout 30s ./...

test-interop:
	$(GO) test -race -tags=interop -timeout 300s ./...

# Integration tests that drive the built binaries end-to-end through a
# real TCP socket, nc-backed ProxyCommand, and tmux where available.
# Skip-tolerant: tests that need nc/tmux/scp will t.Skip if the tool
# is absent. Pair with `make build` in CI.
e2e:
	$(GO) test -race -timeout 120s -run 'TestE2E|TestSCP|TestProxyCommand|TestGosshAutoloads' -v ./...

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
