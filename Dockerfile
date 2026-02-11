# --- Builder ---
FROM golang:1.25-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod ./

RUN go mod download

COPY . .

# CGO_ENABLED=0 creates a statically linked binary (no dependency on OS libraries)
RUN CGO_ENABLED=0 GOOS=linux go build -o mailvetter cmd/api/main.go


# --- Runner ---
FROM alpine:latest

RUN apk --no-cache add ca-certificates

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /home/appuser/

COPY --from=builder /app/mailvetter .

RUN chown appuser:appgroup ./mailvetter

EXPOSE 8080

CMD ["./mailvetter"]