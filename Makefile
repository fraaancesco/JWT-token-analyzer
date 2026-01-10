.PHONY: build run swagger clean install-tools rebuild test

# Binary name
BINARY_NAME=jwt-token-analyzer

# Build the application
build: swagger
	@echo "Building $(BINARY_NAME)..."
	go build -o $(BINARY_NAME) ./cmd/server

# Run the application
run: build
	@echo "Running $(BINARY_NAME)..."
	./$(BINARY_NAME)

# Generate Swagger documentation
swagger:
	@echo "Generating Swagger documentation..."
	swag init -g cmd/server/main.go -o docs

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -f $(BINARY_NAME)
	rm -rf docs/

# Install development tools
install-tools:
	@echo "Installing tools..."
	go install github.com/swaggo/swag/cmd/swag@latest

# Rebuild from scratch
rebuild: clean build

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod tidy
	go mod download

# Build for Docker (static binary)
build-static:
	@echo "Building static binary..."
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o $(BINARY_NAME) ./cmd/server

# Docker build
docker-build:
	@echo "Building Docker image..."
	docker build -t $(BINARY_NAME):latest .

# Docker run
docker-run:
	@echo "Running Docker container..."
	docker run -p 8082:8082 $(BINARY_NAME):latest
