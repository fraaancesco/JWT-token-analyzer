package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fraaancesco/jwt-token-analyzer/internal/testutil"
	"github.com/fraaancesco/jwt-token-analyzer/pkg/models"
	"github.com/gin-gonic/gin"
)

func newTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := NewAnalyzeHandler()
	r.GET("/health", h.HealthCheck)
	r.POST("/analyze", h.Analyze)
	r.POST("/decode", h.Decode)
	return r
}

func do(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	newTestRouter().ServeHTTP(w, req)
	return w
}

func token(lifetime time.Duration) string {
	now := time.Now()
	return testutil.Token(map[string]any{"alg": "RS256", "typ": "JWT"}, map[string]any{
		"iss": "i", "sub": "s", "aud": "a", "jti": "j",
		"iat": now.Unix(), "exp": now.Add(lifetime).Unix(),
	}, "sig")
}

func TestHealthCheck(t *testing.T) {
	w := do(t, http.MethodGet, "/health", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "healthy") {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
}

func TestAnalyze(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"tokens": []string{token(time.Hour), "bad"}})
	w := do(t, http.MethodPost, "/analyze", string(body))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
	var report models.Report
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 2 || !report.Results[0].IsValid || report.Results[1].IsValid {
		t.Fatalf("unexpected report %+v", report)
	}
	if report.AnalysisDate == "" {
		t.Error("missing analysis date")
	}
}

func TestAnalyzeOptions(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"tokens":                    []string{token(3 * time.Hour)},
		"check_expiration":          true,
		"max_token_lifetime_hours":  2,
		"warn_token_lifetime_hours": 1,
	})
	w := do(t, http.MethodPost, "/analyze", string(body))
	if !strings.Contains(w.Body.String(), "VERY_LONG_EXPIRATION") {
		t.Fatalf("custom lifetime not applied: %s", w.Body)
	}

	body, _ = json.Marshal(map[string]any{"tokens": []string{token(3 * time.Hour)}, "warn_token_lifetime_hours": 1})
	if w := do(t, http.MethodPost, "/analyze", string(body)); !strings.Contains(w.Body.String(), `"LONG_EXPIRATION"`) {
		t.Fatalf("custom warn lifetime not applied: %s", w.Body)
	}
}

func TestAnalyzeBadRequest(t *testing.T) {
	for _, body := range []string{"{", `{"tokens":[]}`} {
		if w := do(t, http.MethodPost, "/analyze", body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d", body, w.Code)
		}
	}
}

func TestDecode(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"token": token(time.Hour)})
	w := do(t, http.MethodPost, "/decode", string(body))
	var resp DecodeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || resp.Header == nil || resp.Header.Algorithm != "RS256" || resp.Payload == nil {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
}

func TestDecodeBadRequest(t *testing.T) {
	if w := do(t, http.MethodPost, "/decode", `{}`); w.Code != http.StatusBadRequest {
		t.Fatalf("got %d", w.Code)
	}
}
