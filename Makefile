VERSION := $(shell cat VERSION)
BINARY := bin/pipelineguard
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test fmt vet clean

build:
	mkdir -p bin
	go build \
		-trimpath \
		-ldflags "$(LDFLAGS)" \
		-o $(BINARY) \
		./cmd/pipelineguard

test:
	go test ./...

fmt:
	gofmt -w cmd internal

vet:
	go vet ./...

clean:
	rm -rf bin
