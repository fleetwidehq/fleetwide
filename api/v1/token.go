package v1

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// DeploymentKeyToken is a deployment key as pasted into FLEETWIDE_KEY:
// everything a supervisor needs to join, in one value.
//
// Wire form: "fw1." + base64url(JSON). It is not encrypted.
type DeploymentKeyToken struct {
	ConsoleURL string `json:"url"`
	AppKey     string `json:"app"`
	Secret     string `json:"secret"`
	// CASHA256 is the hex SHA-256 of the Console CA certificate (DER). When
	// set, the Supervisor pins the server chain to it during enrollment, so a
	// self-signed Console needs no CA file on the device. Empty when the
	// Console serves a publicly trusted certificate.
	CASHA256 string `json:"ca_sha256,omitempty"`
	// Label is informational (customer / site) for the install snippet.
	Label string `json:"label,omitempty"`
}

const keyPrefix = "fw1."

// Encode serialises the key.
func (t DeploymentKeyToken) Encode() string {
	b, _ := json.Marshal(t)
	return keyPrefix + base64.RawURLEncoding.EncodeToString(b)
}

// ErrBadKey is returned for malformed keys.
var ErrBadKey = errors.New("malformed deployment key (expected fw1.<base64>)")

// DecodeKey parses a deployment key.
func DecodeKey(s string) (*DeploymentKeyToken, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, keyPrefix) {
		return nil, ErrBadKey
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, keyPrefix))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadKey, err)
	}
	var t DeploymentKeyToken
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadKey, err)
	}
	if t.ConsoleURL == "" || t.AppKey == "" || t.Secret == "" {
		return nil, fmt.Errorf("%w: missing url, app or secret", ErrBadKey)
	}
	return &t, nil
}
