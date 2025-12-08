FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

# CGO_ENABLED=0: Disable CGO for static binary
# -ldflags="-s -w": Strip debug information to reduce binary size
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o main ./cmd/main.go

FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

RUN adduser -D -u 1000 appuser

WORKDIR /app

COPY --from=builder /app/main .

RUN chown appuser:appuser main

# Switch to non-root user
USER 1000

ARG API_PORT=8080
ENV API_PORT=${API_PORT}
EXPOSE ${API_PORT}

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:${API_PORT}/health || exit 1

ENTRYPOINT ["./main"]
