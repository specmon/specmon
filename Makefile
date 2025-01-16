GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
BINARY_NAME=specmon
TEST_FOLDER=./...

all: build test

default: build

build:
	$(GOMOD) tidy
	$(GOBUILD) -v .

test:
	$(GOTEST) $(TEST_FOLDER) -v

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
