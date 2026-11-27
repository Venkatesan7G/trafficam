package keyseal

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// TPM2 seals the key inside a TPM 2.0 "sealed data object".
//
// How it works: the TPM derives a storage key (the standard ECC P-256 SRK)
// from a secret that never leaves the chip, and the database key is stored
// as a child object of it. The key file holds that object's public and
// encrypted private parts; only this TPM can load and unseal them. The
// commands that carry the key are encrypted (salted HMAC session with AES
// parameter encryption), so it does not cross the motherboard in the clear.
//
// Deliberate choices:
//   - No PCR policy. Binding to boot measurements would also stop a
//     tampered boot chain, but every kernel, bootloader or firmware update
//     would then lock the user out of their own history. Not worth it here.
//   - Empty owner authorisation is assumed (the default on almost every PC).
//     If an owner password is set, this method reports unavailable and the
//     next method is used.
type TPM2 struct {
	// Open connects to the TPM. Linux uses /dev/tpmrm0; tests use swtpm.
	Open func() (transport.TPMCloser, error)
	Name string // method name, e.g. "linux-tpm2"
}

func (t *TPM2) Method() string { return t.Name }

func (t *TPM2) Available() error {
	tpm, err := t.Open()
	if err != nil {
		return err
	}
	defer tpm.Close()
	srk, err := createSRK(tpm)
	if err != nil {
		return err
	}
	flush(tpm, srk.ObjectHandle)
	return nil
}

func (t *TPM2) Seal(key []byte) ([]byte, error) {
	tpm, err := t.Open()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()
	srk, err := createSRK(tpm)
	if err != nil {
		return nil, err
	}
	defer flush(tpm, srk.ObjectHandle)
	sess, err := session(srk, false)
	if err != nil {
		return nil, err
	}
	rsp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: srk.ObjectHandle, Name: srk.Name, Auth: sess},
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: key}),
		}},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true, // cannot be moved to another TPM
				FixedParent:  true,
				UserWithAuth: true,
				NoDA:         true, // empty auth: dictionary-attack lockout is pointless
			},
		}),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("tpm2 create: %w", err)
	}
	pub := tpm2.Marshal(rsp.OutPublic)
	priv := tpm2.Marshal(rsp.OutPrivate)
	out := binary.BigEndian.AppendUint16(nil, uint16(len(pub)))
	out = append(out, pub...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(priv)))
	return append(out, priv...), nil
}

func (t *TPM2) Unseal(blob []byte) ([]byte, error) {
	pubB, privB, ok := splitTPMBlob(blob)
	if !ok {
		return nil, fmt.Errorf("%w: malformed TPM blob", ErrSealMismatch)
	}
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubB)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSealMismatch, err)
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privB)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSealMismatch, err)
	}
	tpm, err := t.Open()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer tpm.Close()
	srk, err := createSRK(tpm)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer flush(tpm, srk.ObjectHandle)
	sess, err := session(srk, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	loaded, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: srk.ObjectHandle, Name: srk.Name, Auth: sess},
		InPrivate:    *priv,
		InPublic:     *pub,
	}.Execute(tpm)
	if err != nil {
		return nil, classifyTPM("tpm2 load", err)
	}
	defer flush(tpm, loaded.ObjectHandle)
	sess, err = session(srk, true)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	rsp, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{Handle: loaded.ObjectHandle, Name: loaded.Name, Auth: sess},
	}.Execute(tpm)
	if err != nil {
		return nil, classifyTPM("tpm2 unseal", err)
	}
	return rsp.OutData.Buffer, nil
}

// classifyTPM: errors that mean "this blob does not belong to this TPM"
// (copied, tampered, or the TPM was cleared) become ErrSealMismatch; anything
// else (busy, out of memory, retry) is ErrUnavailable so nothing is destroyed.
func classifyTPM(what string, err error) error {
	for _, rc := range []tpm2.TPMRC{tpm2.TPMRCIntegrity, tpm2.TPMRCBinding, tpm2.TPMRCSize,
		tpm2.TPMRCValue, tpm2.TPMRCKey, tpm2.TPMRCAuthFail, tpm2.TPMRCBadAuth} {
		if errors.Is(err, rc) {
			return fmt.Errorf("%w: %s: %v", ErrSealMismatch, what, err)
		}
	}
	return fmt.Errorf("%w: %s: %v", ErrUnavailable, what, err)
}

func createSRK(tpm transport.TPM) (*tpm2.CreatePrimaryResponse, error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("tpm2 create storage key: %w", err)
	}
	return rsp, nil
}

// session is a one-use HMAC session salted to the SRK that encrypts the
// first command parameter (EncryptIn: the key going into Create) or the
// first response parameter (EncryptOut: the key coming out of Unseal).
func session(srk *tpm2.CreatePrimaryResponse, out bool) (tpm2.Session, error) {
	dir := tpm2.EncryptIn
	if out {
		dir = tpm2.EncryptOut
	}
	pub, err := srk.OutPublic.Contents()
	if err != nil {
		return nil, err
	}
	return tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
		tpm2.AESEncryption(128, dir),
		tpm2.Salted(srk.ObjectHandle, *pub)), nil
}

func flush(tpm transport.TPM, h tpm2.TPMHandle) {
	_, _ = tpm2.FlushContext{FlushHandle: h}.Execute(tpm)
}

func splitTPMBlob(b []byte) (pub, priv []byte, ok bool) {
	next := func() ([]byte, bool) {
		if len(b) < 2 {
			return nil, false
		}
		n := int(binary.BigEndian.Uint16(b))
		if len(b) < 2+n {
			return nil, false
		}
		v := b[2 : 2+n]
		b = b[2+n:]
		return v, true
	}
	var ok1, ok2 bool
	pub, ok1 = next()
	priv, ok2 = next()
	return pub, priv, ok1 && ok2 && len(b) == 0
}
