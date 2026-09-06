.PHONY: build build-native build-wslc test vet

ifeq ($(OS),Windows_NT)
build: build-wslc
else
build: build-native
endif

build-wslc:
	powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/build-wslc.ps1

build-native:
	mkdir -p bin
	CGO_ENABLED=1 go build -buildvcs=false -trimpath -ldflags="-w -s" -o bin/hostdiscovery ./cmd/hostdiscovery

test:
	go test ./...

vet:
	go vet ./...
