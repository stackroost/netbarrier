.PHONY: all build test clean

all: build

build:
	./scripts/build.sh

test:
	go test ./...

clean:
	rm -rf bin/