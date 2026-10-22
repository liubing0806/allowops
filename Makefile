VERSION ?= dev
BINARIES := allowops allowops-gateway allowops-agent allowops-exec
BUF_VERSION := v1.73.0
STATICCHECK_VERSION := v0.8.2
GOVULNCHECK_VERSION := v1.9.0
GO_LICENSES_VERSION := v2.0.1
GORELEASER_VERSION := v2.18.3
SQLC_VERSION := v1.30.0
OPA_VERSION = $(shell go list -m -f '{{.Version}}' github.com/open-policy-agent/opa)
FUZZTIME ?= 30s
ALLOWED_LICENSES := MIT,BSD-2-Clause,BSD-3-Clause,Apache-2.0,ISC,MPL-2.0

.PHONY: build $(BINARIES) test examples-check script-checks lint vuln generate web-build licenses package opa-test scale bench-opa vm fuzz e2e local-up local-down

build: $(BINARIES)

$(BINARIES):
	mkdir -p bin
	CGO_ENABLED=0 go build -ldflags "-X main.version=$(VERSION)" -o bin/$@ ./cmd/$@

examples-check: allowops
	python3 test/examples/check_examples.py ./bin/allowops examples/catalog

test: examples-check
	go test -race -timeout=20m ./...

# Explicit, local-only acceptance runs; excluded from the normal test path.
scale: allowops-gateway
	ALLOWOPS_REQUIRE_DOCKER=1 go test -tags=scale ./test/scale -run '^TestScale$$' -count=1 -v -timeout=30m

bench-opa:
	go test ./internal/gateway/authz -run '^$$' -bench '^BenchmarkBatchPolicy500Rules1000Hosts$$' -benchmem -count=3

vm: build
	ALLOWOPS_REQUIRE_DOCKER=1 go test -tags=vm ./test/vm -run '^TestMatrix$$' -count=1 -v -timeout=60m

package:
	GO_LICENSES_VERSION=$(GO_LICENSES_VERSION) go run github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION) release --snapshot --clean --skip=sign

opa-test:
	go run github.com/open-policy-agent/opa@$(OPA_VERSION) test internal/gateway/authz/

fuzz:
	@set -eu; \
	listing="$$(go test -list '^Fuzz' ./...)"; \
	targets="$$(printf '%s\n' "$$listing" | awk '/^Fuzz/ { targets[++n] = $$1 } /^ok[[:space:]]/ { for (i = 1; i <= n; i++) print $$2, targets[i]; n = 0 }')"; \
	test -n "$$targets"; \
	printf '%s\n' "$$targets" | while read -r package target; do \
		printf 'Fuzzing %s/%s for %s\n' "$$package" "$$target" "$(FUZZTIME)"; \
		go test "$$package" -run '^$$' -fuzz "^$$target$$" -fuzztime "$(FUZZTIME)" -parallel=4 -timeout=0; \
	done

# Python checks of the packaging scripts and the CI dist-drift check (needs PyYAML).
script-checks:
	python3 deploy/packaging/test-postinstall-nosudo.py
	python3 test/ci-dist-check.py

lint: script-checks
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

generate:
	cd web && CI=true pnpm install --frozen-lockfile
	go run github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION) generate
	go run github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION) generate

web-build:
	cd web && pnpm build

e2e:
	./test/e2e/run.sh

local-up:
	./deploy/compose/local-up.sh

local-down:
	./deploy/compose/local-down.sh

# The project's MIT license is separate from the third-party allowlist.
licenses:
	go run github.com/google/go-licenses/v2@$(GO_LICENSES_VERSION) check ./... --include_tests --ignore github.com/liubing0806/allowops --allowed_licenses=$(ALLOWED_LICENSES)
