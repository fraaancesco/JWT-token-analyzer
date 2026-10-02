package testutil

import (
	"strings"
	"testing"
)

func TestToken(t *testing.T) {
	token := Token(map[string]string{"alg": "HS256"}, map[string]int{"exp": 1}, "sig")
	if strings.Count(token, ".") != 2 || !strings.HasPrefix(token, "eyJ") || !strings.HasSuffix(token, ".sig") {
		t.Fatalf("unexpected token %q", token)
	}
}

func TestEncodePanicsOnInvalidValue(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic")
		}
	}()
	Encode(make(chan int))
}
