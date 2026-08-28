BINARY := bin/pipelineguard

.PHONY: build test fmt vet clean

build:
	mkdir -p bin
	go build -o $(BINARY) ./cmd/pipelineguard

test:
	go test ./...

fmt:
	gofmt -w cmd internal

vet:
	go vet ./...

clean:
	rm -rf bin
