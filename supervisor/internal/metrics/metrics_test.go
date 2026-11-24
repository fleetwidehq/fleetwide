package metrics

import "testing"

func TestParsers(t *testing.T) {
	if cpuLimitV2("max 100000") != 0 || cpuLimitV2("200000 100000") != 2 || cpuLimitV2("50000 100000") != 0.5 {
		t.Fatal("cpu.max parsing")
	}
	if countCPUList("0-3,8,10-11") != 7 || countCPUList("") != 0 {
		t.Fatal("cpuset list")
	}
	st := kv("usage_usec 123\nuser_usec 100\nMemTotal:       16000 kB\n")
	if st["usage_usec"] != 123 || st["MemTotal"] != 16000 {
		t.Fatalf("kv: %v", st)
	}
	if parseUint("max") != 0 || parseUint(" 42\n") != 42 {
		t.Fatal("parseUint")
	}
	var s Sampler
	m := s.Sample() // whatever the host offers; must not panic and must fill the ceilings
	if m == nil || m.CPUCores <= 0 {
		t.Fatalf("sample: %+v", m)
	}
}
