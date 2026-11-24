package tunnel

import (
	"bytes"
	"testing"
)

func TestPreambleRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteOpen(&buf, 3000); err != nil {
		t.Fatal(err)
	}
	port, err := ReadOpen(&buf)
	if err != nil || port != 3000 {
		t.Fatalf("got %d %v", port, err)
	}
	if err := WriteOpen(&buf, 70000); err == nil {
		t.Fatal("port out of range must fail")
	}
	buf.Reset()
	if err := WriteResult(&buf, Result{Status: Refused, Message: "connection refused"}); err != nil {
		t.Fatal(err)
	}
	res, err := ReadResult(&buf)
	if err != nil || res.Status != Refused || res.Message != "connection refused" {
		t.Fatalf("got %+v %v", res, err)
	}
}
