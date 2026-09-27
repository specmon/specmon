GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
BINARY_NAME=specmon
TEST_FOLDER=./...
GO_LICENSES=github.com/google/go-licenses/v2@v2.0.1
LICENSES_FILE=THIRD_PARTY_LICENSES.txt

all: build test

default: build

build:
	$(GOMOD) tidy
	$(GOBUILD) -v .

test:
	$(GOTEST) $(TEST_FOLDER) -v

third-party-licenses:
	$(GOCMD) run $(GO_LICENSES) report ./... \
		--template .github/third-party-licenses.tpl > $(LICENSES_FILE)

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME) $(LICENSES_FILE)
