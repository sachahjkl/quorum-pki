FROM golang:1.25.1-alpine AS build
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0
RUN go build -o /out/demo ./cmd/demo && go build -o /out/node ./cmd/node && go build -o /out/verifier ./cmd/verifier && go build -o /out/request ./cmd/request && GOOS=js GOARCH=wasm go build -o web/simulator.wasm ./cmd/wasm && cp /usr/local/go/lib/wasm/wasm_exec.js web/wasm_exec.js
FROM alpine:3.22
WORKDIR /app
COPY --from=build /out/ /app/bin/
COPY --from=build /src/web /app/web
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app/bin/demo"]
