# Artifact Review — build targets
#
# usage:
#   make             # build for current platform into ./dist/
#   make all         # build linux+darwin+windows (amd64) into ./dist/
#   make run         # run with no case
#   make run-demo    # run pointed at ./testdata/case
#   make clean

BIN := artifact-review
PKG := ./cmd/artifact-review
DIST := dist

# version stamping (best-effort; non-fatal if no git)
VERSION := $(shell git describe --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: default
default: build

.PHONY: build
build:
	mkdir -p $(DIST)
	go build $(LDFLAGS) -o $(DIST)/$(BIN) $(PKG)

.PHONY: all
all: linux darwin windows

.PHONY: linux
linux:
	mkdir -p $(DIST)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/$(BIN)-linux-amd64 $(PKG)
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(DIST)/$(BIN)-linux-arm64 $(PKG)

.PHONY: darwin
darwin:
	mkdir -p $(DIST)
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/$(BIN)-darwin-amd64 $(PKG)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(DIST)/$(BIN)-darwin-arm64 $(PKG)

.PHONY: windows
windows:
	mkdir -p $(DIST)
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/$(BIN)-windows-amd64.exe $(PKG)
	GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o $(DIST)/$(BIN)-windows-arm64.exe $(PKG)

.PHONY: run
run: build
	$(DIST)/$(BIN)

.PHONY: run-demo
run-demo: build
	$(DIST)/$(BIN) --case ./testdata/case

.PHONY: test
test:
	go test ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: clean
clean:
	rm -rf $(DIST)
