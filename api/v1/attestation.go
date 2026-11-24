package v1

// Hardware identity. A fleet may require every container to prove the
// hardware it runs on before it enrolls. The supervisor asks for a
// challenge, answers it with evidence only that hardware can produce, and
// sends the evidence with its enrollment.

// Identity providers.
const (
	IdentityTPM = "tpm" // TPM 2.0, discrete or firmware
)

// EnrollChallengeRequest opens a hardware-backed enrollment. It carries the
// same deployment key an enrollment does.
type EnrollChallengeRequest struct {
	AppKey   string `json:"app_key"`
	Secret   string `json:"secret"`
	Provider string `json:"provider"`
	// TPM: the endorsement key and the attestation key as TPMT_PUBLIC, and
	// the endorsement certificate (DER) when the chip carries one.
	EKPub  []byte `json:"ek_pub,omitempty"`
	EKCert []byte `json:"ek_cert,omitempty"`
	AKPub  []byte `json:"ak_pub,omitempty"`
}

// EnrollChallengeResponse is the console's challenge. Use is false when the
// fleet does not ask for hardware identity; the supervisor then enrolls
// without it.
type EnrollChallengeResponse struct {
	Use         bool   `json:"use"`
	ChallengeID string `json:"challenge_id,omitempty"`
	Nonce       []byte `json:"nonce,omitempty"`
	// TPM: a credential only the chip holding both keys can open, and the
	// PCRs to quote.
	CredentialBlob  []byte `json:"credential_blob,omitempty"`
	EncryptedSecret []byte `json:"encrypted_secret,omitempty"`
	PCRs            []int  `json:"pcrs,omitempty"`
}

// Attestation is the answer to a challenge, sent with the enrollment.
type Attestation struct {
	Provider    string `json:"provider"`
	ChallengeID string `json:"challenge_id"`
	// Credential is the secret recovered from the challenge.
	Credential []byte `json:"credential,omitempty"`
	// Quote is a TPMS_ATTEST over the nonce and the PCRs, QuoteSig its
	// TPMT_SIGNATURE by the attestation key, PCRs the SHA-256 values quoted.
	Quote    []byte         `json:"quote,omitempty"`
	QuoteSig []byte         `json:"quote_sig,omitempty"`
	PCRs     map[int][]byte `json:"pcrs,omitempty"`
	// KeyPub is the TPMT_PUBLIC of the key the certificate request is signed
	// with; KeyCertify and KeyCertifySig are the attestation key's
	// certification of it.
	KeyPub        []byte `json:"key_pub,omitempty"`
	KeyCertify    []byte `json:"key_certify,omitempty"`
	KeyCertifySig []byte `json:"key_certify_sig,omitempty"`
}
