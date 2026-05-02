BINARY   := lan-radar
GO       := /usr/local/go/bin/go
GOFLAGS  :=

.PHONY: all build run clean deps

all: build

deps:
	$(GO) mod tidy

build: deps
	$(GO) build $(GOFLAGS) -o $(BINARY) .

# Build with race detector for development
build-dev: deps
	$(GO) build -race $(GOFLAGS) -o $(BINARY) .

run: build
	sudo -E ./$(BINARY)

# Set capabilities so you can run without sudo each time
install-cap: build
	sudo setcap cap_net_raw+ep ./$(BINARY)
	@echo "Done. Now run ./$(BINARY) without sudo."

clean:
	rm -f $(BINARY)
