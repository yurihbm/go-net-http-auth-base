FROM golang:1.27.4-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

# CGO_ENABLED=0: Disable CGO for static binary
# -ldflags="-s -w": Strip debug information to reduce binary size
# -trimpath: Remove local filesystem paths from the binary
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o api ./cmd/api
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o promote-admin ./cmd/promote-admin

FROM alpine:3.24

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

RUN adduser -D -u 1000 appuser

WORKDIR /app

COPY --from=builder /app/api /app/promote-admin ./

# Switch to non-root user
USER 1000

ARG API_PORT=8080
ENV API_PORT=${API_PORT}
EXPOSE ${API_PORT}

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:${API_PORT}/health || exit 1

ENTRYPOINT ["./api"]
