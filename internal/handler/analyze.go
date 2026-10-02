package handler

import (
	"net/http"
	"time"

	"github.com/fraaancesco/jwt-token-analyzer/internal/analyzer"
	"github.com/fraaancesco/jwt-token-analyzer/pkg/models"
	"github.com/gin-gonic/gin"
)

// AnalyzeHandler handles JWT analysis requests
type AnalyzeHandler struct {
	defaultOptions analyzer.Options
}

// NewAnalyzeHandler creates a new AnalyzeHandler
func NewAnalyzeHandler() *AnalyzeHandler {
	return &AnalyzeHandler{
		defaultOptions: analyzer.DefaultOptions(),
	}
}

// AnalyzeRequest represents the incoming request body
type AnalyzeRequest struct {
	Tokens             []string `json:"tokens" binding:"required,min=1" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	CheckExpiration    *bool    `json:"check_expiration,omitempty" example:"true"`
	MaxTokenLifetimeH  *int     `json:"max_token_lifetime_hours,omitempty" example:"168"`
	WarnTokenLifetimeH *int     `json:"warn_token_lifetime_hours,omitempty" example:"24"`
}

// Analyze godoc
// @Summary Analyze JWT tokens
// @Description Analyzes one or more JWT tokens for security vulnerabilities and best practices
// @Tags analyze
// @Accept json
// @Produce json
// @Param request body AnalyzeRequest true "JWT tokens to analyze"
// @Success 200 {object} models.Report "Analysis report"
// @Failure 400 {object} map[string]string "Bad request"
// @Router /analyze [post]
func (h *AnalyzeHandler) Analyze(c *gin.Context) {
	var req AnalyzeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build options
	opts := h.defaultOptions

	if req.CheckExpiration != nil {
		opts.CheckExpiration = *req.CheckExpiration
	}
	if req.MaxTokenLifetimeH != nil {
		opts.MaxTokenLifetime = time.Duration(*req.MaxTokenLifetimeH) * time.Hour
	}
	if req.WarnTokenLifetimeH != nil {
		opts.WarnTokenLifetime = time.Duration(*req.WarnTokenLifetimeH) * time.Hour
	}

	// Analyze each token
	results := make([]models.AnalysisResult, 0, len(req.Tokens))
	for _, token := range req.Tokens {
		result := analyzer.Analyze(token, opts)
		results = append(results, result)
	}

	report := models.Report{
		AnalysisDate: time.Now().Format(time.RFC3339),
		Results:      results,
	}

	c.JSON(http.StatusOK, report)
}

// DecodeRequest represents a simple decode request
type DecodeRequest struct {
	Token string `json:"token" binding:"required" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

// DecodeResponse represents the decoded JWT without security analysis
type DecodeResponse struct {
	Token     string                 `json:"token"`
	Header    *models.JWTHeader      `json:"header,omitempty"`
	Payload   *models.DecodedPayload `json:"payload,omitempty"`
	Signature string                 `json:"signature,omitempty"`
	TokenInfo *models.TokenInfo      `json:"token_info,omitempty"`
	Error     *string                `json:"error,omitempty"`
}

// Decode godoc
// @Summary Decode a JWT token
// @Description Decodes a JWT token and returns its header, payload, and metadata without security analysis
// @Tags decode
// @Accept json
// @Produce json
// @Param request body DecodeRequest true "JWT token to decode"
// @Success 200 {object} DecodeResponse "Decoded token"
// @Failure 400 {object} map[string]string "Bad request"
// @Router /decode [post]
func (h *AnalyzeHandler) Decode(c *gin.Context) {
	var req DecodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Use analyzer with minimal checks
	opts := analyzer.Options{
		CheckExpiration: true,
	}

	result := analyzer.Analyze(req.Token, opts)

	response := DecodeResponse{
		Token:     result.Token,
		Header:    result.Header,
		Payload:   result.Payload,
		Signature: result.Signature,
		TokenInfo: result.TokenInfo,
		Error:     result.Error,
	}

	c.JSON(http.StatusOK, response)
}

// HealthCheck godoc
// @Summary Health check
// @Description Returns the health status of the service
// @Tags health
// @Produce json
// @Success 200 {object} map[string]string "Service is healthy"
// @Router /health [get]
func (h *AnalyzeHandler) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "jwt-token-analyzer",
	})
}
