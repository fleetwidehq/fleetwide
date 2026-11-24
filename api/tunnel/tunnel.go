// Package tunnel is the wire protocol between an access-capable supervisor and
// the Fleetwide proxy. The supervisor upgrades one mTLS HTTP connection to
// Protocol, the two sides multiplex it, and every multiplexed stream starts
// with a fixed preamble naming the container port to reach. Bytes then flow
// unchanged: the supervisor never parses HTTP, and the preamble cannot carry a
// host, so a stream only ever reaches 127.0.0.1:<port> inside the supervisor's
// own container.
package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// Path and Protocol of the Upgrade request the supervisor sends to the proxy.
	Path     = "/v1/tunnel"
	Protocol = "fleetwide-tunnel/1"
	// HeaderSupervisor carries the supervisor version on the Upgrade request.
	HeaderSupervisor = "X-Fleetwide-Supervisor"
	// HeaderPorts lists the ports the supervisor will accept, comma separated.
	HeaderPorts = "X-Fleetwide-Ports"

	version = 1
	maxMsg  = 512
)

// Status of an opened stream, sent by the supervisor after the preamble.
type Status uint8

const (
	OK             Status = 0
	Refused        Status = 1 // nothing listens on the port (connection refused)
	PortNotAllowed Status = 2 // port is not in the supervisor's allowlist
	Timeout        Status = 3 // dial timed out
	Unavailable    Status = 4 // supervisor is in production mode or shutting down
)

func (s Status) String() string {
	switch s {
	case OK:
		return "ok"
	case Refused:
		return "refused"
	case PortNotAllowed:
		return "port not allowed"
	case Timeout:
		return "timeout"
	case Unavailable:
		return "unavailable"
	}
	return fmt.Sprintf("status %d", uint8(s))
}

// Result is the supervisor's answer to an open request.
type Result struct {
	Status  Status
	Message string
}

// WriteOpen sends the stream preamble: [version][port uint16 BE].
func WriteOpen(w io.Writer, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("tunnel: port %d out of range", port)
	}
	var b [3]byte
	b[0] = version
	binary.BigEndian.PutUint16(b[1:], uint16(port))
	_, err := w.Write(b[:])
	return err
}

// ReadOpen reads the preamble and returns the requested port.
func ReadOpen(r io.Reader) (int, error) {
	var b [3]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	if b[0] != version {
		return 0, fmt.Errorf("tunnel: unsupported preamble version %d", b[0])
	}
	port := int(binary.BigEndian.Uint16(b[1:]))
	if port == 0 {
		return 0, errors.New("tunnel: port 0")
	}
	return port, nil
}

// WriteResult sends [status][len uint16 BE][message].
func WriteResult(w io.Writer, res Result) error {
	msg := []byte(res.Message)
	if len(msg) > maxMsg {
		msg = msg[:maxMsg]
	}
	b := make([]byte, 3+len(msg))
	b[0] = byte(res.Status)
	binary.BigEndian.PutUint16(b[1:], uint16(len(msg)))
	copy(b[3:], msg)
	_, err := w.Write(b)
	return err
}

// ReadResult reads the supervisor's answer.
func ReadResult(r io.Reader) (Result, error) {
	var h [3]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return Result{}, err
	}
	n := int(binary.BigEndian.Uint16(h[1:]))
	if n > maxMsg {
		return Result{}, fmt.Errorf("tunnel: result message too long (%d)", n)
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return Result{}, err
	}
	return Result{Status: Status(h[0]), Message: string(msg)}, nil
}

// Refusal is the JSON body of a 403 on the Upgrade request.
type Refusal struct {
	Code    string `json:"code"` // access_disabled | unknown_installation | certificate_superseded | no_access
	Message string `json:"message"`
}
