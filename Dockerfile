# Multi-stage build for Hermes Guard plugin validation
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go vet ./... && go test -v -race ./... && echo "All checks passed"

FROM alpine:latest
COPY --from=builder /app /plugin
CMD ["echo", "Hermes Guard plugin validated — copy /plugin to Traefik plugins directory"]
