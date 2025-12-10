# syntax=docker/dockerfile:1

# Build stage
FROM golang:1.24-alpine AS builder
# Install build dependencies for CGO (sqlite3)
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Build with CGO enabled for sqlite3 support
RUN CGO_ENABLED=1 GOOS=linux go build -o kubeshadow ./main.go

# Final image
FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/kubeshadow .
ENTRYPOINT ["./kubeshadow"] 