# Build stage
FROM golang:1.27-alpine3.24 AS builder

# Install build dependencies
RUN apk add --no-cache git

# Install swag for Swagger documentation
RUN go install github.com/swaggo/swag/cmd/swag@v1.16.6

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Generate Swagger documentation
RUN swag init -g cmd/server/main.go -o docs

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o jwt-token-analyzer ./cmd/server

# Runtime stage
FROM alpine:3.24

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/jwt-token-analyzer .

# Set environment variables
ENV GIN_MODE=release
ENV SERVER_PORT=8082

# Expose port
EXPOSE 8082

# Run the application
CMD ["./jwt-token-analyzer"]
