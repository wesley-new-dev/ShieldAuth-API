FROM golang:1.22-alpine AS builder
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0  GOOS=linux go build -ldflags="-w -s" -o main ./cmd/main.go
FROM alpine:3.19
RUN apk update && apk upgrade && rm -rf /var/cache/apk/*
RUN adduser -D -g '' appuser
WORKDIR /app
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder --chown=appuser:appuser /app/main .
COPY --from=builder --chown=appuser:appuser /app/internal/database/migrations ./internal/database/migrations
USER appuser
EXPOSE 8080
ENTRYPOINT [ "./main" ]