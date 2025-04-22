BIN="./bin"
SRC=$(shell find . -name "*.go")
CURRENT_TAG=$(shell git describe --tags --abbrev=0)

GOLANGCI := $(shell command -v golangci-lint 2>/dev/null)
RICHGO := $(shell command -v richgo 2>/dev/null)
GOTESTFMT := $(shell command -v gotestfmt 2>/dev/null)

.PHONY: fmt lint build test clean compile compress

default: all

all: fmt lint build test release

release: clean build compile compress

fmt:
	$(info ******************** checking formatting ********************)
	@test -z $(shell gofmt -l $(SRC)) || (gofmt -d $(SRC); exit 1)

lint:
	$(info ******************** running lint tools ********************)
	golangci-lint run -c .golangci-lint.yml -v ./... --timeout 10m

test:
	$(info ******************** running tests ********************)
    ifeq ($(GITHUB_ACTIONS), true)
        ifndef GOTESTFMT
			$(warning "could not find gotestfmt in $(PATH), running: go install github.com/gotesttools/gotestfmt/v2/cmd/gotestfmt@latest")
			$(shell go install github.com/gotesttools/gotestfmt/v2/cmd/gotestfmt@latest)
        endif
		go test -json -v ./... 2>&1 | tee coverage/gotest.log | gotestfmt
	else ifneq ($(GITLAB_CI),)
        ifndef GOTESTFMT
			$(warning "could not find gotestfmt in $(PATH), running: go install github.com/gotesttools/gotestfmt/v2/cmd/gotestfmt@latest")
			$(shell go install github.com/gotesttools/gotestfmt/v2/cmd/gotestfmt@latest)
        endif
		go test -json -v ./... 2>&1 | tee coverage/gotest.log | gotestfmt -c gitlab
    else
        ifndef RICHGO
			$(warning "could not find richgo in $(PATH), running: go install github.com/kyoh86/richgo@latest")
			$(shell go install github.com/kyoh86/richgo@latest)
        endif
		richgo test -v ./...
    endif

changelog:
	$(info ******************** running git-cliff updating CHANGELOG.md ********************)
	git-cliff -o CHANGELOG.md

clean:
	rm -rf $(BIN) 2>/dev/null

build:
	go env -w GOFLAGS=-mod=mod
	go mod tidy
	go build -v -trimpath -ldflags="-s -w" .

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
