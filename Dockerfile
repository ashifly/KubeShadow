# syntax=docker/dockerfile:1

# Build stage
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o kubeshadow ./main.go

# Final image
FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/kubeshadow .
ENTRYPOINT ["./kubeshadow"] 