SHELL := /bin/bash
BIN="./bin"
SRC=$(shell git ls-files --cached --others --exclude-standard '*.go')
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
CURRENT_TAG := $(VERSION)
LDFLAGS := -s -w -X github.com/mr-pmillz/gophlare/internal/version.version=$(VERSION)
FLARE_SPEC_URL := https://api.docs.flare.io/api-reference/spec
FLARE_SPECS := firework-v2-openapi firework-v4-openapi

.PHONY: fmt lint build test clean compile compress generate openapi-specs

default: all

all: fmt lint build test release

release: clean build compile compress

fmt:
	$(info ******************** checking formatting ********************)
	@test -z "$$(gofmt -l $(SRC))" || (gofmt -d $(SRC); exit 1)

lint:
	$(info ******************** running lint tools ********************)
	golangci-lint run -c .golangci-lint.yml -v ./... --timeout 10m

test:
	@mkdir -p coverage
	@if pgrep -f '(^|/)go test' >/dev/null; then \
		go test -p=1 -race -covermode=atomic -coverprofile=coverage/coverage.out ./...; \
	else \
		go test -race -covermode=atomic -coverprofile=coverage/coverage.out ./...; \
	fi

generate:
	$(info ******************** generating Flare API models ********************)
	go generate ./flareapi/...

openapi-specs:
	$(info ******************** downloading Flare OpenAPI specs ********************)
	@for spec in $(FLARE_SPECS); do \
		curl -fsSL "$(FLARE_SPEC_URL)/$$spec.json" -o "flareapi/openapi/$$spec.json" || exit 1; \
	done

changelog:
	$(info ******************** running git-cliff updating CHANGELOG.md ********************)
	git-cliff -o CHANGELOG.md

clean:
	rm -rf $(BIN) 2>/dev/null

build:
	go build -mod=readonly -v -trimpath -ldflags="$(LDFLAGS)" .

compile:
	GOOS=linux GOARCH=amd64 go build -o bin/linux/amd64/gophlare-$(CURRENT_TAG)-linux-amd64 -trimpath -ldflags="$(LDFLAGS)" .
	GOOS=linux GOARCH=arm64 go build -o bin/linux/arm64/gophlare-$(CURRENT_TAG)-linux-arm64 -trimpath -ldflags="$(LDFLAGS)" .
	GOOS=darwin GOARCH=amd64 go build -o bin/darwin/amd64/gophlare-$(CURRENT_TAG)-x86_64-macos-darwin_amd64 -trimpath -ldflags="$(LDFLAGS)" .
	GOOS=darwin GOARCH=arm64 go build -o bin/darwin/arm64/gophlare-$(CURRENT_TAG)-x86_64-macos-darwin_arm64 -trimpath -ldflags="$(LDFLAGS)" .

compress:
	gzip -9 bin/linux/amd64/gophlare-$(CURRENT_TAG)-linux-amd64
	gzip -9 bin/linux/arm64/gophlare-$(CURRENT_TAG)-linux-arm64
	gzip -9 bin/darwin/amd64/gophlare-$(CURRENT_TAG)-x86_64-macos-darwin_amd64
	gzip -9 bin/darwin/arm64/gophlare-$(CURRENT_TAG)-x86_64-macos-darwin_arm64
