GO ?= go
TLC_JAR ?= tools/tla2tools.jar
export CGO_ENABLED=0
.PHONY: test vet demo scenarios wasm wasm-test bench formal build cross clean
build:
	mkdir -p bin
	$(GO) build -o bin/demo ./cmd/demo
	$(GO) build -o bin/node ./cmd/node
	$(GO) build -o bin/verifier ./cmd/verifier
	$(GO) build -o bin/request ./cmd/request
test:
	$(GO) test ./...
vet:
	$(GO) vet ./...
demo:
	$(GO) run ./cmd/demo
scenarios:
	$(GO) run ./cmd/demo -check
wasm:
	GOOS=js GOARCH=wasm $(GO) build -o web/simulator.wasm ./cmd/wasm
	cp "$$( $(GO) env GOROOT )/lib/wasm/wasm_exec.js" web/wasm_exec.js
wasm-test: wasm
	node scripts/wasm-smoke.cjs
bench:
	$(GO) test -run '^$$' -bench . -benchtime=1s ./internal/...
formal:
	java -XX:+UseParallelGC -Xmx2g -cp $(TLC_JAR) tlc2.TLC -workers 2 -config formal/DistributedPKI.cfg formal/DistributedPKI.tla
	java -cp $(TLC_JAR) tlc2.TLC -config formal/IntersectionFive.cfg formal/QuorumIntersection.tla
	java -cp $(TLC_JAR) tlc2.TLC -config formal/IntersectionSeven.cfg formal/QuorumIntersection.tla
cross:
	mkdir -p bin
	GOOS=windows GOARCH=amd64 $(GO) build -o bin/demo-windows.exe ./cmd/demo
	GOOS=darwin GOARCH=arm64 $(GO) build -o bin/demo-macos ./cmd/demo
	GOOS=linux GOARCH=arm64 $(GO) build -o bin/demo-linux-arm64 ./cmd/demo
clean:
	rm -rf bin states
