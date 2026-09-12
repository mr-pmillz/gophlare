SHELL := /bin/bash
BIN="./bin"
SRC=$(shell git ls-files --cached --others --exclude-standard '*.go')
CURRENT_TAG=$(shell git describe --tags --abbrev=0)

.PHONY: fmt lint build test clean compile compress

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

changelog:
	$(info ******************** running git-cliff updating CHANGELOG.md ********************)
	git-cliff -o CHANGELOG.md

clean:
	rm -rf $(BIN) 2>/dev/null

build:
	go build -mod=readonly -v -trimpath -ldflags="-s -w" .

compile:
	GOOS=linux GOARCH=amd64 go build -o bin/linux/amd64/gophlare-$(CURRENT_TAG)-linux-amd64 -trimpath -ldflags="-s -w" main.go
	GOOS=linux GOARCH=arm64 go build -o bin/linux/arm64/gophlare-$(CURRENT_TAG)-linux-arm64 -trimpath -ldflags="-s -w" main.go
	GOOS=darwin GOARCH=amd64 go build -o bin/darwin/amd64/gophlare-$(CURRENT_TAG)-x86_64-macos-darwin_amd64 -trimpath -ldflags="-s -w" main.go
	GOOS=darwin GOARCH=arm64 go build -o bin/darwin/arm64/gophlare-$(CURRENT_TAG)-x86_64-macos-darwin_arm64 -trimpath -ldflags="-s -w" main.go

compress:
	gzip -9 bin/linux/amd64/gophlare-$(CURRENT_TAG)-linux-amd64
	gzip -9 bin/linux/arm64/gophlare-$(CURRENT_TAG)-linux-arm64
	gzip -9 bin/darwin/amd64/gophlare-$(CURRENT_TAG)-x86_64-macos-darwin_amd64
	gzip -9 bin/darwin/arm64/gophlare-$(CURRENT_TAG)-x86_64-macos-darwin_arm64
