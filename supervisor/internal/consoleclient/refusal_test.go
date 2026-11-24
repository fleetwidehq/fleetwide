package consoleclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPostReturnsRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/coded":
			w.WriteHeader(403)
			w.Write([]byte(`{"code":"requirements_unmet","error":"memory 256 MB, needs 1 GB"}`))
		default:
			w.WriteHeader(403)
			w.Write([]byte(`{"error":"invalid or revoked deployment key"}`))
		}
	}))
	defer srv.Close()

	err := post(context.Background(), srv.Client(), srv.URL+"/coded", struct{}{}, nil)
	var ref *Refusal
	if !errors.As(err, &ref) || ref.Code != RequirementsUnmet || ref.Status != 403 || ref.Error() != "memory 256 MB, needs 1 GB" {
		t.Fatalf("want a refusal with its code and message, got %#v", err)
	}
	err = post(context.Background(), srv.Client(), srv.URL+"/plain", struct{}{}, nil)
	if err == nil || errors.As(err, &ref) {
		t.Fatalf("an answer without a code is an ordinary error, got %#v", err)
	}
}
