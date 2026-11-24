BINARY := bin/noctis
MODULE := github.com/Zyrakk/noctis
VERSION ?= dev
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

IMAGE ?= ghcr.io/zyrakk/noctis
TAG ?= dev
IMAGE_CHECK_OUTPUT ?= /tmp/noctis-image-check
COMMIT ?= $(shell git rev-parse HEAD)

.PHONY: build test lint clean docker-build frontend-build frontend-test ci ci-check v2-check v2-e2e image-check image-verify

build: frontend-build
	go build $(LDFLAGS) -o $(BINARY) ./cmd/noctis

frontend-build:
	cd web && npm ci && npm run build

frontend-test: frontend-build
	cd web && npm run test:build

ci: ci-check
	go build $(LDFLAGS) -o $(BINARY) ./cmd/noctis
	$(MAKE) v2-e2e

ci-check: v2-check frontend-test

# Uses an unused output directory; the E2E executes /noctis from the AMD64 image.
image-check:
	python3 ops/rebuild/operations/image_checks.py --output "$(IMAGE_CHECK_OUTPUT)" --version "$(VERSION)" --commit "$(COMMIT)"

image-verify:
	python3 ops/rebuild/operations/image_checks.py --output "$(IMAGE_CHECK_OUTPUT)" --version "$(VERSION)" --commit "$(COMMIT)" --verify

v2-check:
	python3 tools/check_v2_migrations.py
	python3 -m unittest discover -s ops/rebuild/operations -p 'test_*.py'
	python3 -m unittest discover -s ops/rebuild/operations/gates -p 'test_*.py'
	python3 -m unittest discover -s tools/eval
	go build $(LDFLAGS) -o $(BINARY) ./cmd/noctis
	NOCTIS_V2_TEST_BINARY=$(abspath $(BINARY)) python3 ops/rebuild/operations/ci_checks.py

v2-e2e:
	go run ./ops/rebuild/e2e --binary $(BINARY) --browser --product --ai

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/

docker-build:
	docker build --build-arg VERSION=$(TAG) -t $(IMAGE):$(TAG) .
