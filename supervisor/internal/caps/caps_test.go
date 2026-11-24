package caps

import "testing"

func TestNames(t *testing.T) {
	m := Bit(Setfcap) | Bit(Mknod) | Bit(10)
	if got := m.String(); got != "net_bind_service,mknod,setfcap" {
		t.Fatalf("names: %s", got)
	}
	if Mask(0).String() != "none" {
		t.Fatal("empty mask")
	}
	if Bit(63).String() != "cap_63" {
		t.Fatal("an unnamed capability is printed by number")
	}
}

// The two sets do not overlap, and together they are exactly what the
// README promises the supervisor needs.
func TestRequiredAndOptionalAreDisjoint(t *testing.T) {
	if Required&Optional != 0 {
		t.Fatalf("overlap: %s", Required&Optional)
	}
	if got := Required.String(); got != "chown,dac_override,fowner,fsetid,kill,setgid,setuid" {
		t.Fatalf("required: %s", got)
	}
	if got := Optional.String(); got != "mknod,setfcap" {
		t.Fatalf("optional: %s", got)
	}
}
