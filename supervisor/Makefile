GO ?= go
BIN := bin/fleetwide-supervisor
IMAGE ?= fleetwide-supervisor/slim:dev

.PHONY: build build-telemetry build-dev build-all build-linux test vet image matrix clean

# The slim variant: no live logs, no Access tunnel, no telemetry.
build:
	$(GO) build -o $(BIN) ./cmd/fleetwide-supervisor

build-telemetry:
	$(GO) build -tags telemetry -o bin/fleetwide-supervisor-telemetry ./cmd/fleetwide-supervisor

build-dev:
	$(GO) build -tags logs,access,telemetry -o bin/fleetwide-supervisor-developer ./cmd/fleetwide-supervisor

# All three variants must compile.
build-all: build build-telemetry build-dev

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=$$( $(GO) env GOARCH ) $(GO) build -trimpath -ldflags="-s -w" -o bin/fleetwide-supervisor-linux ./cmd/fleetwide-supervisor

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

image:
	docker build -t $(IMAGE) .

# Pull + unpack + exec matrix against public images (needs Docker).
matrix: image
	./scripts/matrix.sh

clean:
	rm -rf bin
