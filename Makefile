.PHONY: test lint build policy-test kind-up kind-down image image-load e2e-up e2e-down e2e-test nic-fixtures-check coverage-doc

IMG ?= ghcr.io/nebari-dev/nebari-user-secrets:dev

# External versions, written only in ci/pins.env; exported to every recipe.
include ci/pins.env
export

test:
	go test ./... -race -cover

lint:
	golangci-lint run

# docs/ci/coverage.md is generated from test/journeys/catalog.yaml; the Tier 1
# catalog test fails when it is stale.
coverage-doc:
	go run ./test/journeys/cmd/coverage > docs/ci/coverage.md

build:
	CGO_ENABLED=0 go build ./...

# K8S_VERSION=<kindest/node tag> runs one version; default: POLICY_K8S_VERSIONS.
policy-test:
	K8S_VERSION=$(K8S_VERSION) bash test/policy/run-all.sh

kind-up:
	bash hack/kind.sh up

kind-down:
	bash hack/kind.sh down

# Multi-arch image as an OCI tarball (no push, no load: a multi-platform image
# cannot be loaded into the classic docker store).
image:
	mkdir -p bin
	docker buildx build --platform linux/amd64,linux/arm64 \
		--build-arg GO_BUILDER_IMAGE=$(GO_BUILDER_IMAGE) \
		--output type=oci,dest=bin/image.oci.tar -t $(IMG) .

# Host-platform image loaded into the local docker store (used by kind).
image-load:
	docker buildx build --load --build-arg GO_BUILDER_IMAGE=$(GO_BUILDER_IMAGE) -t $(IMG) .

# End-to-end cluster us-e2e (kind + Calico + NIC's cluster CA + the chart).
# Kubeconfig: .kube/e2e. e2e-down deletes only us-e2e.
e2e-up: image-load
	IMG=$(IMG) bash test/e2e/setup.sh up

e2e-down:
	bash test/e2e/setup.sh down

e2e-test:
	go test -tags e2e ./test/e2e/... -v -count=1 -timeout 30m

# Manual drift check of the vendored NIC templates against nebari-infrastructure-core
# at NIC_REF (needs gh). Not a CI gate.
NIC_REF ?= $(NIC_FIXTURES_REF)
NIC_FIXTURES = manifests/security/issuers/selfsigned-clusterissuer.yaml \
	manifests/security/issuers/root-ca-certificate.yaml \
	manifests/security/issuers/ca-clusterissuer.yaml \
	manifests/security/trust-bundle/bundle.yaml \
	values/cert-manager/base.yaml \
	values/trust-manager/base.yaml

nic-fixtures-check:
	@set -e; rc=0; for p in $(NIC_FIXTURES); do \
		gh api "repos/nebari-dev/nebari-infrastructure-core/contents/pkg/argocd/templates/$$p?ref=$(NIC_REF)" \
			-H 'Accept: application/vnd.github.raw' | diff -u "test/e2e/fixtures/nic/$$p" - || rc=1; \
	done; \
	if [ $$rc -eq 0 ]; then echo "NIC fixtures match $(NIC_REF)"; else echo "NIC fixtures differ from $(NIC_REF)"; fi; \
	exit $$rc
