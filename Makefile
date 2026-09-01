.PHONY: build test vet build-bpf run

build:
	go build -o bin/sentinel ./cmd/sentinel

test:
	go test ./tests/integration/... -v

vet:
	go vet ./...

build-bpf:
	# Linux only
	clang -O2 -g -target bpf -c src/sentinels/syscall_sentinel.bpf.c -o bin/syscall_sentinel.bpf.o

run: build
	./bin/sentinel --policy config/policy.yaml
