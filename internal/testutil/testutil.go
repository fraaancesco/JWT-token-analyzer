// Package testutil builds JWTs for tests.
package testutil

import (
	"encoding/base64"
	"encoding/json"
)

// Encode returns the base64url (unpadded) JSON encoding of v.
func Encode(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

// Token builds an unsigned-but-signature-shaped JWT from a header and claims.
func Token(header, claims any, signature string) string {
	return Encode(header) + "." + Encode(claims) + "." + signature
}
