// Package tpm is the supervisor's side of TPM 2.0 hardware identity: the
// endorsement key that names the chip, an attestation key that signs quotes
// and certifications, and the signing key behind the container's client
// certificate. All three are primary keys, derived by the chip from its own
// seeds, so nothing is stored outside it and no private key ever leaves it.
package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// SocketEnv names a software TPM to use in place of a device node, as
// "tcp://host:port" or "unix:///path". For development.
const SocketEnv = "FLEETWIDE_TPM_SOCKET"

// Nodes are the device nodes tried in order: the kernel resource manager
// first.
var Nodes = []string{"/dev/tpmrm0", "/dev/tpm0"}

// ErrNoDevice means no TPM is visible to this container.
var ErrNoDevice = errors.New("no TPM device")

// NV indices of the endorsement certificates (TCG EK Credential Profile).
const (
	nvECCEKCert = 0x01c0000a
	nvRSAEKCert = 0x01c00002
)

type key struct {
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
	public []byte // TPMT_PUBLIC
}

// Device is an open TPM with the three keys loaded. It is safe for
// concurrent use.
type Device struct {
	mu     sync.Mutex
	t      transport.TPMCloser
	ekTmpl tpm2.TPMTPublic
	// ek is loaded only while a credential is opened: a TPM holds a handful
	// of keys at a time, and the other two stay loaded for the life of the
	// process.
	ek, ak, tls key
	ekCert      []byte
	tlsPub      *ecdsa.PublicKey
}

// Open opens the TPM this container can see and derives the keys.
func Open() (*Device, error) {
	t, raw, err := openTransport()
	if err != nil {
		return nil, err
	}
	if raw {
		flushTransients(t)
	}
	d, err := newDevice(t)
	if err != nil {
		t.Close()
		return nil, err
	}
	return d, nil
}

// openTransport returns the TPM and whether the connection is a raw one:
// a socket or /dev/tpm0, where nothing cleans up after a client that went
// away, unlike the kernel resource manager behind /dev/tpmrm0.
func openTransport() (transport.TPMCloser, bool, error) {
	if addr := os.Getenv(SocketEnv); addr != "" {
		network, address, ok := strings.Cut(addr, "://")
		if !ok || (network != "tcp" && network != "unix") {
			return nil, false, fmt.Errorf("%s: want tcp://host:port or unix:///path", SocketEnv)
		}
		c, err := net.DialTimeout(network, address, 5*time.Second)
		if err != nil {
			return nil, false, fmt.Errorf("%s: %w", SocketEnv, err)
		}
		return transport.FromReadWriteCloser(&stream{c}), true, nil
	}
	var last error = ErrNoDevice
	for _, p := range Nodes {
		f, err := os.OpenFile(p, os.O_RDWR, 0)
		if err == nil {
			return transport.FromReadWriteCloser(f), !strings.Contains(p, "tpmrm"), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			last = err
		}
	}
	return nil, false, last
}

// flushTransients unloads the keys an earlier client left in the TPM, which
// holds only a handful.
func flushTransients(t transport.TPM) {
	const firstTransient = 0x80000000
	rsp, err := tpm2.GetCapability{Capability: tpm2.TPMCapHandles, Property: firstTransient, PropertyCount: 32}.Execute(t)
	if err != nil {
		return
	}
	handles, err := rsp.CapabilityData.Data.Handles()
	if err != nil {
		return
	}
	for _, h := range handles.Handle {
		tpm2.FlushContext{FlushHandle: h}.Execute(t)
	}
}

// stream makes a byte stream deliver one TPM response per Read, the way a
// device node does: the response header says how long it is.
type stream struct{ net.Conn }

func (s *stream) Read(p []byte) (int, error) {
	const header = 10 // tag, size, response code
	if len(p) < header {
		return 0, io.ErrShortBuffer
	}
	if _, err := io.ReadFull(s.Conn, p[:header]); err != nil {
		return 0, err
	}
	size := int(binary.BigEndian.Uint32(p[2:6]))
	if size < header || size > len(p) {
		return 0, fmt.Errorf("tpm: response of %d bytes", size)
	}
	if _, err := io.ReadFull(s.Conn, p[header:size]); err != nil {
		return 0, err
	}
	return size, nil
}

func newDevice(t transport.TPMCloser) (*Device, error) {
	d := &Device{t: t}
	var err error
	d.ekTmpl = tpm2.ECCEKTemplate
	if d.ek, err = d.primary(tpm2.TPMRHEndorsement, d.ekTmpl); err != nil {
		// a chip without the ECC endorsement key
		d.ekTmpl = tpm2.RSAEKTemplate
		if d.ek, err = d.primary(tpm2.TPMRHEndorsement, d.ekTmpl); err != nil {
			return nil, fmt.Errorf("endorsement key: %w", err)
		}
		d.ekCert = d.nvRead(nvRSAEKCert)
	} else {
		d.ekCert = d.nvRead(nvECCEKCert)
	}
	d.flush(d.ek)
	if d.ak, err = d.primary(tpm2.TPMRHEndorsement, signingTemplate("fleetwide attestation", true)); err != nil {
		return nil, fmt.Errorf("attestation key: %w", err)
	}
	if d.tls, err = d.primary(tpm2.TPMRHOwner, signingTemplate("fleetwide identity", false)); err != nil {
		return nil, fmt.Errorf("identity key: %w", err)
	}
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](d.tls.public)
	if err != nil {
		return nil, err
	}
	if d.tlsPub, err = eccPublic(pub); err != nil {
		return nil, err
	}
	return d, nil
}

// signingTemplate is an ECDSA P-256 signing key that cannot leave the chip.
// A restricted one signs only what the chip itself produced, which is what
// makes its quotes and certifications evidence. The label makes each key a
// different one from the same seed.
func signingTemplate(label string, restricted bool) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
			Restricted:          restricted,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme:  tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
			CurveID: tpm2.TPMECCNistP256,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: label32(label)},
			Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		}),
	}
}

func label32(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func (d *Device) primary(hierarchy tpm2.TPMHandle, tmpl tpm2.TPMTPublic) (key, error) {
	rsp, err := tpm2.CreatePrimary{PrimaryHandle: hierarchy, InPublic: tpm2.New2B(tmpl)}.Execute(d.t)
	if err != nil {
		return key{}, err
	}
	return key{handle: rsp.ObjectHandle, name: rsp.Name, public: rsp.OutPublic.Bytes()}, nil
}

// nvRead returns the contents of an NV index, or nil when it is absent or
// unreadable.
func (d *Device) nvRead(index uint32) []byte {
	h := tpm2.TPMHandle(index)
	pub, err := tpm2.NVReadPublic{NVIndex: h}.Execute(d.t)
	if err != nil {
		return nil
	}
	info, err := pub.NVPublic.Contents()
	if err != nil {
		return nil
	}
	var out []byte
	const chunk = 512
	for len(out) < int(info.DataSize) {
		n := int(info.DataSize) - len(out)
		if n > chunk {
			n = chunk
		}
		rsp, err := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: h, Name: pub.NVName},
			Size:       uint16(n),
			Offset:     uint16(len(out)),
		}.Execute(d.t)
		if err != nil {
			return nil
		}
		out = append(out, rsp.Data.Buffer...)
	}
	return out
}

func (d *Device) flush(k key) {
	tpm2.FlushContext{FlushHandle: k.handle}.Execute(d.t)
}

// Close flushes the keys and closes the TPM.
func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.flush(d.tls)
	d.flush(d.ak)
	return d.t.Close()
}

// EKPub is the endorsement key as a TPMT_PUBLIC: what names this chip.
func (d *Device) EKPub() []byte { return d.ek.public }

// EKCert is the endorsement certificate (DER), or nil when the chip has none.
func (d *Device) EKCert() []byte { return d.ekCert }

// AKPub is the attestation key as a TPMT_PUBLIC.
func (d *Device) AKPub() []byte { return d.ak.public }

// KeyPub is the identity key as a TPMT_PUBLIC.
func (d *Device) KeyPub() []byte { return d.tls.public }

// Fingerprint is the SHA-256 of the endorsement key, in hex.
func (d *Device) Fingerprint() string { return Fingerprint(d.ek.public) }

// Fingerprint is the SHA-256 of a TPMT_PUBLIC, in hex.
func Fingerprint(public []byte) string {
	h := sha256.Sum256(public)
	return fmt.Sprintf("%x", h[:])
}

func endorsementPolicy(t transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
	_, err := tpm2.PolicySecret{AuthHandle: tpm2.TPMRHEndorsement, PolicySession: handle, NonceTPM: nonceTPM}.Execute(t)
	return err
}

// Activate opens a credential made for this chip's endorsement key and
// attestation key, and returns the secret inside.
func (d *Device) Activate(blob, encryptedSecret []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ek, err := d.primary(tpm2.TPMRHEndorsement, d.ekTmpl)
	if err != nil {
		return nil, fmt.Errorf("endorsement key: %w", err)
	}
	defer d.flush(ek)
	rsp, err := tpm2.ActivateCredential{
		ActivateHandle: tpm2.AuthHandle{Handle: d.ak.handle, Name: d.ak.name, Auth: tpm2.PasswordAuth(nil)},
		KeyHandle:      tpm2.AuthHandle{Handle: ek.handle, Name: ek.name, Auth: tpm2.Policy(tpm2.TPMAlgSHA256, 16, endorsementPolicy)},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: blob},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: encryptedSecret},
	}.Execute(d.t)
	if err != nil {
		return nil, fmt.Errorf("activate credential: %w", err)
	}
	return rsp.CertInfo.Buffer, nil
}

// Quote signs the SHA-256 values of the given PCRs, with the nonce, using
// the attestation key. It returns the TPMS_ATTEST, its TPMT_SIGNATURE and
// the values quoted.
func (d *Device) Quote(nonce []byte, pcrs []int) (quote, sig []byte, values map[int][]byte, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if values, err = d.readPCRs(pcrs); err != nil {
		return nil, nil, nil, err
	}
	rsp, err := tpm2.Quote{
		SignHandle:     tpm2.AuthHandle{Handle: d.ak.handle, Name: d.ak.name, Auth: tpm2.PasswordAuth(nil)},
		QualifyingData: tpm2.TPM2BData{Buffer: nonce},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
		PCRSelect:      selection(pcrs),
	}.Execute(d.t)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("quote: %w", err)
	}
	return rsp.Quoted.Bytes(), tpm2.Marshal(rsp.Signature), values, nil
}

// PCRs reads the SHA-256 values of the given PCRs.
func (d *Device) PCRs(pcrs []int) (map[int][]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.readPCRs(pcrs)
}

func selection(pcrs []int) tpm2.TPMLPCRSelection {
	u := make([]uint, len(pcrs))
	for i, p := range pcrs {
		u[i] = uint(p)
	}
	return tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(u...)}}}
}

// readPCRs reads PCR values; a TPM returns a few per call.
func (d *Device) readPCRs(pcrs []int) (map[int][]byte, error) {
	want := append([]int{}, pcrs...)
	sort.Ints(want)
	out := map[int][]byte{}
	for len(want) > 0 {
		rsp, err := tpm2.PCRRead{PCRSelectionIn: selection(want)}.Execute(d.t)
		if err != nil {
			return nil, fmt.Errorf("read PCRs: %w", err)
		}
		if len(rsp.PCRValues.Digests) == 0 || len(rsp.PCRSelectionOut.PCRSelections) == 0 {
			return nil, errors.New("read PCRs: the TPM has no SHA-256 bank for them")
		}
		mask := rsp.PCRSelectionOut.PCRSelections[0].PCRSelect
		i, rest := 0, want[:0:0]
		for _, p := range want {
			if p/8 < len(mask) && mask[p/8]&(1<<(p%8)) != 0 && i < len(rsp.PCRValues.Digests) {
				out[p] = rsp.PCRValues.Digests[i].Buffer
				i++
			} else {
				rest = append(rest, p)
			}
		}
		if len(rest) == len(want) {
			return nil, errors.New("read PCRs: the TPM returned none of them")
		}
		want = rest
	}
	return out, nil
}

// CertifyKey has the attestation key certify the identity key, with the
// nonce: proof that the key behind the certificate lives in the same chip.
func (d *Device) CertifyKey(nonce []byte) (info, sig []byte, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rsp, err := tpm2.Certify{
		ObjectHandle:   tpm2.AuthHandle{Handle: d.tls.handle, Name: d.tls.name, Auth: tpm2.PasswordAuth(nil)},
		SignHandle:     tpm2.AuthHandle{Handle: d.ak.handle, Name: d.ak.name, Auth: tpm2.PasswordAuth(nil)},
		QualifyingData: tpm2.TPM2BData{Buffer: nonce},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
	}.Execute(d.t)
	if err != nil {
		return nil, nil, fmt.Errorf("certify: %w", err)
	}
	return rsp.CertifyInfo.Bytes(), tpm2.Marshal(rsp.Signature), nil
}

func eccPublic(pub *tpm2.TPMTPublic) (*ecdsa.PublicKey, error) {
	parms, err := pub.Parameters.ECCDetail()
	if err != nil {
		return nil, err
	}
	point, err := pub.Unique.ECC()
	if err != nil {
		return nil, err
	}
	return tpm2.ECDSAPub(parms, point)
}

// Signer signs with the identity key. It is the private key of the
// container's client certificate.
func (d *Device) Signer() crypto.Signer { return signer{d} }

type signer struct{ d *Device }

func (s signer) Public() crypto.PublicKey { return s.d.tlsPub }

func (s signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var alg tpm2.TPMAlgID
	switch opts.HashFunc() {
	case crypto.SHA256:
		alg = tpm2.TPMAlgSHA256
	case crypto.SHA384:
		alg = tpm2.TPMAlgSHA384
	case crypto.SHA512:
		alg = tpm2.TPMAlgSHA512
	default:
		return nil, fmt.Errorf("tpm: unsupported hash %v", opts.HashFunc())
	}
	d := s.d
	d.mu.Lock()
	defer d.mu.Unlock()
	rsp, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{Handle: d.tls.handle, Name: d.tls.name, Auth: tpm2.PasswordAuth(nil)},
		Digest:    tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: alg}),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
	}.Execute(d.t)
	if err != nil {
		return nil, fmt.Errorf("tpm sign: %w", err)
	}
	ecc, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(ecc.SignatureR.Buffer), new(big.Int).SetBytes(ecc.SignatureS.Buffer)})
}
