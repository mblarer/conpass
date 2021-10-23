.PHONY: test
test:
	go test

.PHONY: vet
vet:
	for pkg in . {benchmarks,example}/*.go; do \
		go vet $$pkg || exit 1; \
	done
