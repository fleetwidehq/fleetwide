package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sort"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/tpm"
)

// cmdTPM prints what this container sees of the device's TPM: the
// fingerprint a deployment registers, and the boot measurements.
func cmdTPM() error {
	d, err := tpm.Open()
	if errors.Is(err, tpm.ErrNoDevice) {
		return errors.New("no TPM is visible to this container; pass it in with --device /dev/tpmrm0")
	}
	if err != nil {
		return fmt.Errorf("TPM: %w", err)
	}
	defer d.Close()
	fmt.Printf("fingerprint  %s\n", d.Fingerprint())
	issuer := "none on this chip"
	if der := d.EKCert(); len(der) > 0 {
		issuer = "unreadable"
		if c, err := x509.ParseCertificate(der); err == nil {
			issuer = c.Issuer.String()
		}
	}
	fmt.Printf("certificate  %s\n", issuer)
	pcrs := []int{0, 1, 2, 3, 4, 5, 6, 7}
	values, err := d.PCRs(pcrs)
	if err != nil {
		return err
	}
	sort.Ints(pcrs)
	for _, p := range pcrs {
		fmt.Printf("pcr %-2d       %x\n", p, values[p])
	}
	return nil
}
