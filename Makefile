.PHONY: build build-native build-wslc test vet prepare

GO_VERSION := 1.27.4
ifeq ($(OS),Windows_NT)
PROJECT_OUTPUT_ROOT ?= V:/Development/go-hostdiscovery
build: build-wslc
else
PROJECT_OUTPUT_ROOT ?= /mnt/v/Development/go-hostdiscovery
build: build-native
endif

export TEMP := $(PROJECT_OUTPUT_ROOT)/tmp/make
export TMP := $(TEMP)
export TMPDIR := $(TEMP)
export GOTMPDIR := $(TEMP)
export GOCACHE := $(PROJECT_OUTPUT_ROOT)/caches/go-build
export GOMODCACHE := $(PROJECT_OUTPUT_ROOT)/caches/go-modules
export GOWORK := off
export GOTOOLCHAIN := go$(GO_VERSION)

prepare:
ifeq ($(OS),Windows_NT)
	powershell.exe -NoProfile -Command "New-Item -ItemType Directory -Force -ErrorAction Stop -Path '$(TEMP)', '$(GOCACHE)', '$(GOMODCACHE)', '$(PROJECT_OUTPUT_ROOT)/artifacts/bin' | Out-Null"
else
	@case "$(PROJECT_OUTPUT_ROOT)" in /mnt/v/*) mountpoint -q /mnt/v || { echo "V: is not mounted at /mnt/v; set PROJECT_OUTPUT_ROOT to its mounted project path." >&2; exit 1; } ;; esac
	@test -d "$$(dirname "$(PROJECT_OUTPUT_ROOT)")" || { echo "Development volume is unavailable for $(PROJECT_OUTPUT_ROOT)" >&2; exit 1; }
	mkdir -p "$(TEMP)" "$(GOCACHE)" "$(GOMODCACHE)" "$(PROJECT_OUTPUT_ROOT)/artifacts/bin"
endif

build-wslc:
	powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/build-wslc.ps1

build-native: prepare
	CGO_ENABLED=1 go build -buildvcs=false -trimpath -ldflags="-w -s" -o "$(PROJECT_OUTPUT_ROOT)/artifacts/bin/hostdiscovery" ./cmd/hostdiscovery

test: prepare
	go test ./...

vet: prepare
	go vet ./...
