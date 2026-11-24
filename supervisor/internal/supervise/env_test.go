package supervise

import (
	"strings"
	"testing"
)

func TestMergeEnv(t *testing.T) {
	got := MergeEnv([]string{"PATH=/bin", "MODE=dev", "KEEP=1"}, []string{"MODE=prod", "NEW=x", "broken", "=novalue"})
	if strings.Join(got, ",") != "PATH=/bin,MODE=prod,KEEP=1,NEW=x" {
		t.Fatalf("got %v", got)
	}
	if len(MergeEnv(nil, nil)) != 0 {
		t.Fatal("empty")
	}
}
