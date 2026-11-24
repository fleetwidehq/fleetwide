package tpm

import (
	v1 "github.com/fleetwidehq/fleetwide/api/v1"
)

// Provider names this kind of hardware identity on the wire.
func (d *Device) Provider() string { return v1.IdentityTPM }

// Challenge is what the console needs to challenge this chip: its
// endorsement key and certificate, and the attestation key.
func (d *Device) Challenge() v1.EnrollChallengeRequest {
	return v1.EnrollChallengeRequest{Provider: v1.IdentityTPM, EKPub: d.EKPub(), EKCert: d.EKCert(), AKPub: d.AKPub()}
}

// Answer produces the evidence a challenge asks for: the recovered
// credential, a quote of the PCRs and the certification of the identity key.
func (d *Device) Answer(ch *v1.EnrollChallengeResponse) (*v1.Attestation, error) {
	cred, err := d.Activate(ch.CredentialBlob, ch.EncryptedSecret)
	if err != nil {
		return nil, err
	}
	quote, sig, values, err := d.Quote(ch.Nonce, ch.PCRs)
	if err != nil {
		return nil, err
	}
	info, isig, err := d.CertifyKey(ch.Nonce)
	if err != nil {
		return nil, err
	}
	return &v1.Attestation{
		Provider: v1.IdentityTPM, ChallengeID: ch.ChallengeID, Credential: cred,
		Quote: quote, QuoteSig: sig, PCRs: values,
		KeyPub: d.KeyPub(), KeyCertify: info, KeyCertifySig: isig,
	}, nil
}
