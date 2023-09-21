.PHONY: all clean build
BUILD_DIR = build/bin
DIRS := $(BUILD_DIR)
all: clean build

create_dirs:
	@mkdir -p $(DIRS)
clean:
	@echo "Cleaning..."
	rm -rf $(DIRS)
build: create_dirs
	@echo "Building CLI Version..."
	go build  -trimpath -o $(BUILD_DIR)/cfscanner cmd/cfscanner/main.go

release: create_dirs
	@echo "Building CLI Release Version..."
	go build -ldflags '-s -w' -trimpath -o $(BUILD_DIR)/cfscanner cmd/cli/main.go

test:
	@echo "Running tests..."
	go test $(shell go list ./... | grep -vE 'cmd/mobile')
