package main

import (
	"log"

	"github.com/fraaancesco/jwt-token-analyzer/internal/config"
	"github.com/fraaancesco/jwt-token-analyzer/internal/handler"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	_ "github.com/fraaancesco/jwt-token-analyzer/docs"
)

// @title JWT Token Analyzer API
// @version 1.0
// @description A security analysis tool for JWT tokens. Analyzes JWT structure, claims, and identifies potential security vulnerabilities.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.example.com/support
// @contact.email support@example.com

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8082
// @BasePath /
// @schemes http https

// runServer and logFatalf are variables so tests can replace them.
var (
	runServer = func(r *gin.Engine, addr string) error { return r.Run(addr) }
	logFatalf = log.Fatalf
)

func main() {
	if err := run(config.Load()); err != nil {
		logFatalf("Failed to start server: %v", err)
	}
}

// run configures the router and starts the HTTP server.
func run(cfg *config.Config) error {
	// Set Gin mode
	gin.SetMode(cfg.Server.GinMode)

	router := newRouter()

	// Start server
	addr := ":" + cfg.Server.Port
	log.Printf("Starting JWT Token Analyzer on %s", addr)
	log.Printf("Swagger UI available at http://localhost%s/swagger/index.html", addr)

	return runServer(router, addr)
}

// newRouter creates the router with all the API routes registered.
func newRouter() *gin.Engine {
	router := gin.Default()

	h := handler.NewAnalyzeHandler()

	// Register routes
	router.GET("/health", h.HealthCheck)
	router.POST("/analyze", h.Analyze)
	router.POST("/decode", h.Decode)

	// Swagger documentation
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	return router
}
