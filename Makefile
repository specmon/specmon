GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
BINARY_NAME=specmon
TEST_FOLDER=./...
GO_LICENSES=github.com/google/go-licenses/v2@v2.0.1
LICENSES_FILE=THIRD_PARTY_LICENSES.txt

# The version is the git revision. At a release tag it is the tag without
# its leading v, as in release builds. Otherwise it also contains the
# number of commits since the nearest release tag and the full commit hash,
# or only the hash if no release tag is reachable. It ends in -dirty if
# tracked files are modified. Go's own VCS stamp is disabled, since in a
# submodule worktree it records the enclosing repository.
VERSION=$(or $(shell git describe --tags --match 'v[0-9]*' --always --dirty --abbrev=40 2>/dev/null | sed 's/^v//'),dev)
LDFLAGS=-X github.com/specmon/specmon/cmd.Version=$(VERSION)

all: build test

default: build

build:
	$(GOBUILD) -buildvcs=false -ldflags "$(LDFLAGS)" -v .

tidy:
	$(GOMOD) tidy

test:
	$(GOTEST) $(TEST_FOLDER) -v

third-party-licenses:
	$(GOCMD) run $(GO_LICENSES) report ./... \
		--template .github/third-party-licenses.tpl > $(LICENSES_FILE)

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME) $(LICENSES_FILE)
