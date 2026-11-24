// Package place reports where a container is: a position given in its
// environment, and the cloud region its instance metadata names.
package place

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"
)

// FromEnv parses FLEETWIDE_LOCATION ("latitude,longitude") and
// FLEETWIDE_LOCATION_NAME. It returns nil when no valid position is set.
func FromEnv(getenv func(string) string) *v1.Place {
	lat, lon, ok := ParseCoords(getenv("FLEETWIDE_LOCATION"))
	if !ok {
		return nil
	}
	return &v1.Place{Lat: lat, Lon: lon, Name: strings.TrimSpace(getenv("FLEETWIDE_LOCATION_NAME"))}
}

// ParseCoords reads "latitude,longitude" in decimal degrees.
func ParseCoords(s string) (lat, lon float64, ok bool) {
	a, b, found := strings.Cut(strings.TrimSpace(s), ",")
	if !found {
		return 0, 0, false
	}
	lat, err1 := strconv.ParseFloat(strings.TrimSpace(a), 64)
	lon, err2 := strconv.ParseFloat(strings.TrimSpace(b), 64)
	if err1 != nil || err2 != nil || lat < -90 || lat > 90 || lon < -180 || lon > 180 || (lat == 0 && lon == 0) {
		return 0, 0, false
	}
	return lat, lon, true
}

// Cloud holds the result of the metadata probe.
type Cloud struct {
	mu  sync.Mutex
	val *v1.Cloud
}

// Get returns the detected cloud region, or nil.
func (c *Cloud) Get() *v1.Cloud {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.val
}

// Start probes the metadata service in the background: once now and once
// more a minute later if nothing answered.
func Start(ctx context.Context) *Cloud {
	c := &Cloud{}
	go func() {
		for attempt := 0; attempt < 2; attempt++ {
			if v := Probe(ctx, metadataURL); v != nil {
				c.mu.Lock()
				c.val = v
				c.mu.Unlock()
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Minute):
			}
		}
	}()
	return c
}

// metadataURL is the link-local metadata service of AWS, Google Cloud and Azure.
const metadataURL = "http://169.254.169.254"

// Probe asks the metadata service at base which cloud this is. The three
// providers are asked at once; the first answer is returned.
func Probe(ctx context.Context, base string) *v1.Cloud {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	hc := &http.Client{Transport: &http.Transport{
		Proxy:       nil,
		DialContext: (&net.Dialer{Timeout: 700 * time.Millisecond}).DialContext,
	}}
	defer hc.CloseIdleConnections()
	probes := []func(context.Context, *http.Client, string) *v1.Cloud{aws, gcp, azure}
	out := make(chan *v1.Cloud, len(probes))
	for _, p := range probes {
		go func() { out <- p(ctx, hc, base) }()
	}
	for range probes {
		if v := <-out; v != nil {
			return v
		}
	}
	return nil
}

func fetch(ctx context.Context, hc *http.Client, method, url string, header map[string]string) (string, http.Header) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return "", nil
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	res, err := hc.Do(req)
	if err != nil {
		return "", nil
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return "", nil
	}
	b, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	return strings.TrimSpace(string(b)), res.Header
}

func aws(ctx context.Context, hc *http.Client, base string) *v1.Cloud {
	token, _ := fetch(ctx, hc, "PUT", base+"/latest/api/token", map[string]string{"X-aws-ec2-metadata-token-ttl-seconds": "60"})
	if token == "" {
		return nil
	}
	h := map[string]string{"X-aws-ec2-metadata-token": token}
	region, _ := fetch(ctx, hc, "GET", base+"/latest/meta-data/placement/region", h)
	if !plain(region) {
		return nil
	}
	zone, _ := fetch(ctx, hc, "GET", base+"/latest/meta-data/placement/availability-zone", h)
	if !plain(zone) {
		zone = ""
	}
	return &v1.Cloud{Provider: "aws", Region: region, Zone: zone}
}

func gcp(ctx context.Context, hc *http.Client, base string) *v1.Cloud {
	body, h := fetch(ctx, hc, "GET", base+"/computeMetadata/v1/instance/zone", map[string]string{"Metadata-Flavor": "Google"})
	if body == "" || h.Get("Metadata-Flavor") != "Google" {
		return nil
	}
	// projects/<number>/zones/<region>-<letter>
	zone := body[strings.LastIndex(body, "/")+1:]
	i := strings.LastIndex(zone, "-")
	if !plain(zone) || i <= 0 {
		return nil
	}
	return &v1.Cloud{Provider: "gcp", Region: zone[:i], Zone: zone}
}

func azure(ctx context.Context, hc *http.Client, base string) *v1.Cloud {
	body, _ := fetch(ctx, hc, "GET", base+"/metadata/instance/compute?api-version=2021-02-01&format=json", map[string]string{"Metadata": "true"})
	var doc struct {
		Location string `json:"location"`
		Zone     string `json:"zone"`
	}
	if body == "" || json.Unmarshal([]byte(body), &doc) != nil || !plain(doc.Location) {
		return nil
	}
	if !plain(doc.Zone) {
		doc.Zone = ""
	}
	return &v1.Cloud{Provider: "azure", Region: strings.ToLower(doc.Location), Zone: doc.Zone}
}

// plain reports whether s looks like a region or zone name.
func plain(s string) bool {
	if s == "" || len(s) > 40 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}
