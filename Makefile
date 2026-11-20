.PHONY: test lint build policy-test

test:
	go test ./... -race -cover

lint:
	golangci-lint run

build:
	CGO_ENABLED=0 go build ./...

policy-test:
	bash test/policy/run-all.sh
