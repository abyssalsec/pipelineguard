VERSION := $(shell cat VERSION)
BINARY := bin/pipelineguard
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test race fmt fmt-check vet clean check release

build:
	mkdir -p bin
	go build \
		-trimpath \
		-ldflags "$(LDFLAGS)" \
		-o $(BINARY) \
		./cmd/pipelineguard

test:
	go test ./...

race:
	go test -race ./...

fmt:
	gofmt -w cmd internal

fmt-check:
	@files="$$(gofmt -l cmd internal)"; \
	if [ -n "$$files" ]; then \
		echo "ERROR: gofmt required:"; \
		echo "$$files"; \
		exit 1; \
	fi

vet:
	go vet ./...

check: fmt-check vet test build

release: check
	./scripts/release.sh

clean:
	rm -rf bin dist
