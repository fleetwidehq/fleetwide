package place

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	p := FromEnv(env(map[string]string{"FLEETWIDE_LOCATION": " 12.97 , 77.59 ", "FLEETWIDE_LOCATION_NAME": " Plant 4 "}))
	if p == nil || p.Lat != 12.97 || p.Lon != 77.59 || p.Name != "Plant 4" {
		t.Fatalf("got %+v", p)
	}
	for _, bad := range []string{"", "12.97", "91,10", "10,181", "0,0", "north,east", "1;2"} {
		if p := FromEnv(env(map[string]string{"FLEETWIDE_LOCATION": bad})); p != nil {
			t.Errorf("%q accepted: %+v", bad, p)
		}
	}
}

func TestProbe(t *testing.T) {
	cases := map[string]struct {
		h                      http.HandlerFunc
		provider, region, zone string
	}{
		"aws": {func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "PUT" && r.URL.Path == "/latest/api/token" && r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") != "":
				w.Write([]byte("tok"))
			case r.Header.Get("X-aws-ec2-metadata-token") != "tok":
				w.WriteHeader(401)
			case r.URL.Path == "/latest/meta-data/placement/region":
				w.Write([]byte("ap-south-1"))
			case r.URL.Path == "/latest/meta-data/placement/availability-zone":
				w.Write([]byte("ap-south-1a"))
			default:
				w.WriteHeader(404)
			}
		}, "aws", "ap-south-1", "ap-south-1a"},
		"gcp": {func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/computeMetadata/v1/instance/zone" && r.Header.Get("Metadata-Flavor") == "Google" {
				w.Header().Set("Metadata-Flavor", "Google")
				w.Write([]byte("projects/1234/zones/europe-west4-b"))
				return
			}
			w.WriteHeader(404)
		}, "gcp", "europe-west4", "europe-west4-b"},
		"azure": {func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/metadata/instance/compute" && r.Header.Get("Metadata") == "true" {
				w.Write([]byte(`{"location":"WestEurope","zone":"2","name":"vm"}`))
				return
			}
			w.WriteHeader(404)
		}, "azure", "westeurope", "2"},
		"none": {func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }, "", "", ""},
		"junk": {func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>captive portal</html>")) }, "", "", ""},
	}
	for name, c := range cases {
		ts := httptest.NewServer(c.h)
		got := Probe(context.Background(), ts.URL)
		ts.Close()
		if c.provider == "" {
			if got != nil {
				t.Errorf("%s: got %+v, want nothing", name, got)
			}
			continue
		}
		if got == nil || got.Provider != c.provider || got.Region != c.region || got.Zone != c.zone {
			t.Errorf("%s: got %+v", name, got)
		}
	}
	if got := Probe(context.Background(), "http://127.0.0.1:1"); got != nil {
		t.Errorf("nothing listening: got %+v", got)
	}
}
