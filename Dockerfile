# --- Builder ---
FROM golang:1.25-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./

RUN go mod download

COPY . .

# Build API Binary
# CGO_ENABLED=0 creates a statically linked binary (no dependency on OS libraries)
RUN CGO_ENABLED=0 GOOS=linux go build -o api-server ./cmd/api

# Build Worker Binary
RUN CGO_ENABLED=0 GOOS=linux go build -o worker-process cmd/worker/main.go


# --- Runner ---
FROM alpine:latest

RUN apk --no-cache add ca-certificates

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /home/appuser/

COPY --from=builder /app/api-server .
COPY --from=builder /app/worker-process .

RUN chown appuser:appgroup ./

USER appuser
