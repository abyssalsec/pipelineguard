VERSION := $(shell cat VERSION)
BINARY := bin/pipelineguard
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test fmt fmt-check vet clean check

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

clean:
	rm -rf bin
