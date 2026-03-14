BINARY := bin/noctis
MODULE := github.com/Zyrakk/noctis
VERSION ?= dev
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

IMAGE ?= ghcr.io/zyrakk/noctis
TAG ?= dev

.PHONY: build test lint clean docker-build

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/noctis

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/

docker-build:
	docker build --build-arg VERSION=$(TAG) -t $(IMAGE):$(TAG) .
