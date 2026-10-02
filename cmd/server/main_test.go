package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fraaancesco/jwt-token-analyzer/internal/config"
	"github.com/gin-gonic/gin"
)

func TestNewRouter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := newRouter()
	for _, path := range []string{"/health", "/swagger/doc.json"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Errorf("GET %s = %d", path, w.Code)
		}
	}
}

func TestRun(t *testing.T) {
	t.Cleanup(func(old func(*gin.Engine, string) error) func() {
		return func() { runServer = old }
	}(runServer))

	var gotAddr string
	runServer = func(_ *gin.Engine, addr string) error {
		gotAddr = addr
		return nil
	}
	cfg := &config.Config{Server: config.ServerConfig{Port: "1234", GinMode: gin.TestMode}}
	if err := run(cfg); err != nil || gotAddr != ":1234" {
		t.Fatalf("run() = %v, addr %q", err, gotAddr)
	}
}

func TestMain_FailsWhenServerCannotStart(t *testing.T) {
	oldRun, oldFatal := runServer, logFatalf
	t.Cleanup(func() { runServer, logFatalf = oldRun, oldFatal })

	t.Setenv("GIN_MODE", gin.TestMode)
	runServer = func(*gin.Engine, string) error { return errors.New("port in use") }
	called := false
	logFatalf = func(string, ...any) { called = true }

	main()
	if !called {
		t.Fatal("main must call logFatalf when the server fails")
	}
}

func TestMain_Succeeds(t *testing.T) {
	oldRun, oldFatal := runServer, logFatalf
	t.Cleanup(func() { runServer, logFatalf = oldRun, oldFatal })

	t.Setenv("GIN_MODE", gin.TestMode)
	runServer = func(*gin.Engine, string) error { return nil }
	logFatalf = func(string, ...any) { t.Fatal("unexpected fatal") }
	main()
}

func TestDefaultRunServer(t *testing.T) {
	// An invalid address makes the real gin server fail immediately.
	if err := runServer(gin.New(), "invalid-address"); err == nil {
		t.Fatal("expected an error for an invalid address")
	}
}
