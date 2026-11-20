.PHONY: test lint build policy-test kind-up kind-down

test:
	go test ./... -race -cover

lint:
	golangci-lint run

build:
	CGO_ENABLED=0 go build ./...

policy-test:
	bash test/policy/run-all.sh

kind-up:
	bash hack/kind.sh up

kind-down:
	bash hack/kind.sh down
