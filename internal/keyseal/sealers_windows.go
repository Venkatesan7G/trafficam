//go:build windows

package keyseal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// platformSealers on Windows: TPM-backed first, then plain DPAPI. DPAPI is
// part of every Windows install, so there is always a working method.
func platformSealers() []Sealer {
	return []Sealer{&WindowsTPM{KeyName: windowsTPMKeyName}, &DPAPI{}}
}

// dpapiEntropy is mixed into every DPAPI call so other programs running as
// the same account cannot unseal our blob just by calling
// CryptUnprotectData on it (they would also need this value: a speed bump,
// not a wall, since it is public in the source).
var dpapiEntropy = []byte("trafficam-keyseal-dpapi-v1")

// DPAPI seals with the Windows Data Protection API, tied to the Windows
// account trafficam runs as (LocalSystem for the service).
//
// Limit: DPAPI's master keys live on the same disk, protected by the account
// password (for LocalSystem, by machine secrets on that disk). Someone with
// the whole disk and the right tools can recover them. WindowsTPM fixes that.
type DPAPI struct{}

func (DPAPI) Method() string   { return "dpapi" }
func (DPAPI) Available() error { return nil }

func (DPAPI) Seal(key []byte) ([]byte, error) { return dpapiProtect(key) }

func (DPAPI) Unseal(blob []byte) ([]byte, error) {
	out, err := dpapiUnprotect(blob)
	if err != nil {
		// Wrong account, other machine, corrupted, or the account's DPAPI
		// keys were lost (admin password reset): all mean "cannot open".
		return nil, fmt.Errorf("%w: dpapi: %v", ErrSealMismatch, err)
	}
	return out, nil
}

func dpapiProtect(data []byte) ([]byte, error) {
	in := blob(data)
	ent := blob(dpapiEntropy)
	var out windows.DataBlob
	name, _ := windows.UTF16PtrFromString("trafficam database key")
	if err := windows.CryptProtectData(&in, name, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	return takeBlob(&out), nil
}

func dpapiUnprotect(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty blob")
	}
	in := blob(data)
	ent := blob(dpapiEntropy)
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	return takeBlob(&out), nil
}

func blob(b []byte) windows.DataBlob {
	if len(b) == 0 {
		return windows.DataBlob{}
	}
	return windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// takeBlob copies a DPAPI output buffer and frees it.
func takeBlob(b *windows.DataBlob) []byte {
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(b.Data)))
	return append([]byte(nil), unsafe.Slice(b.Data, b.Size)...)
}

// WindowsTPM seals with an RSA-2048 key that lives inside the TPM (the
// "Microsoft Platform Crypto Provider"), then wraps the result with DPAPI.
// Opening the key file needs both this PC's TPM chip and this Windows
// account, so a copied disk or a copied folder is useless elsewhere.
//
// The TPM key is created once under the name KeyName in the account's key
// store, and never leaves the chip. If it is deleted or the TPM is cleared,
// the database key is gone for good.
type WindowsTPM struct {
	KeyName string
}

const windowsTPMKeyName = "trafficam-database-key-seal"

func (w *WindowsTPM) Method() string { return "windows-tpm" }

func (w *WindowsTPM) Available() error {
	prov, err := openPCP()
	if err != nil {
		return err
	}
	ncryptFree(prov)
	return nil
}

func (w *WindowsTPM) Seal(key []byte) ([]byte, error) {
	prov, err := openPCP()
	if err != nil {
		return nil, err
	}
	defer ncryptFree(prov)
	k, err := ncryptOpenKey(prov, w.KeyName)
	if errors.Is(err, errBadKeyset) {
		k, err = ncryptCreateKey(prov, w.KeyName)
	}
	if err != nil {
		return nil, err
	}
	defer ncryptFree(k)
	ct, err := ncryptCrypt(procNCryptEncrypt, k, key)
	if err != nil {
		return nil, fmt.Errorf("NCryptEncrypt: %w", err)
	}
	inner := binary.BigEndian.AppendUint16(nil, uint16(len(ct)))
	inner = append(inner, ct...)
	return dpapiProtect(inner)
}

func (w *WindowsTPM) Unseal(sealed []byte) ([]byte, error) {
	inner, err := dpapiUnprotect(sealed)
	if err != nil {
		return nil, fmt.Errorf("%w: dpapi layer: %v", ErrSealMismatch, err)
	}
	if len(inner) < 2 || int(binary.BigEndian.Uint16(inner))+2 != len(inner) {
		return nil, fmt.Errorf("%w: malformed TPM blob", ErrSealMismatch)
	}
	prov, err := openPCP()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer ncryptFree(prov)
	k, err := ncryptOpenKey(prov, w.KeyName)
	if errors.Is(err, errBadKeyset) {
		return nil, fmt.Errorf("%w: the TPM key %q no longer exists (deleted, or the TPM was cleared)", ErrSealMismatch, w.KeyName)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer ncryptFree(k)
	key, err := ncryptCrypt(procNCryptDecrypt, k, inner[2:])
	if err != nil {
		return nil, classifyNCrypt("NCryptDecrypt", err)
	}
	return key, nil
}

// DeleteKey removes the TPM key (tests and the tamper response use it; once
// it is gone every blob sealed with it is unreadable).
func (w *WindowsTPM) DeleteKey() error {
	prov, err := openPCP()
	if err != nil {
		return err
	}
	defer ncryptFree(prov)
	k, err := ncryptOpenKey(prov, w.KeyName)
	if errors.Is(err, errBadKeyset) {
		return nil
	}
	if err != nil {
		return err
	}
	// NCryptDeleteKey frees the handle itself, even on failure.
	return ncryptStatus(procNCryptDeleteKey.Call(k, ncryptSilentFlag))
}

// ---- NCrypt (ncrypt.dll) plumbing. x/sys/windows does not wrap it. ----

var (
	modNCrypt                     = windows.NewLazySystemDLL("ncrypt.dll")
	procNCryptOpenStorageProvider = modNCrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptOpenKey             = modNCrypt.NewProc("NCryptOpenKey")
	procNCryptCreatePersistedKey  = modNCrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptSetProperty         = modNCrypt.NewProc("NCryptSetProperty")
	procNCryptFinalizeKey         = modNCrypt.NewProc("NCryptFinalizeKey")
	procNCryptEncrypt             = modNCrypt.NewProc("NCryptEncrypt")
	procNCryptDecrypt             = modNCrypt.NewProc("NCryptDecrypt")
	procNCryptFreeObject          = modNCrypt.NewProc("NCryptFreeObject")
	procNCryptDeleteKey           = modNCrypt.NewProc("NCryptDeleteKey")
)

const (
	ncryptSilentFlag   = 0x40 // never show UI
	ncryptPadOAEPFlag  = 0x4
	statusNTEBadKeyset = 0x80090016
	statusNTEBadData   = 0x80090005
)

var errBadKeyset = errors.New("NTE_BAD_KEYSET: key does not exist")

type ncryptError uint32

func (e ncryptError) Error() string { return fmt.Sprintf("SECURITY_STATUS 0x%08X", uint32(e)) }

func ncryptStatus(r1, _ uintptr, _ error) error {
	switch s := uint32(r1); s {
	case 0:
		return nil
	case statusNTEBadKeyset:
		return errBadKeyset
	default:
		return ncryptError(s)
	}
}

// classifyNCrypt: bad data and TPM format errors (0x8028_00xx..0x8028_08FF,
// excluding the 0x8028_09xx warnings such as "retry") mean the blob does
// not match this TPM key; anything else may be temporary.
func classifyNCrypt(what string, err error) error {
	var e ncryptError
	if errors.As(err, &e) {
		s := uint32(e)
		if s == statusNTEBadData || (s&0xFFFF0000 == 0x80280000 && s&0xFFFF < 0x900) {
			return fmt.Errorf("%w: %s: %v", ErrSealMismatch, what, err)
		}
	}
	return fmt.Errorf("%w: %s: %v", ErrUnavailable, what, err)
}

func utf16(s string) *uint16 { p, _ := windows.UTF16PtrFromString(s); return p }

func openPCP() (uintptr, error) {
	if err := modNCrypt.Load(); err != nil {
		return 0, err
	}
	var h uintptr
	err := ncryptStatus(procNCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(utf16("Microsoft Platform Crypto Provider"))), 0))
	if err != nil {
		return 0, fmt.Errorf("no usable TPM (Microsoft Platform Crypto Provider): %w", err)
	}
	return h, nil
}

func ncryptOpenKey(prov uintptr, name string) (uintptr, error) {
	var k uintptr
	err := ncryptStatus(procNCryptOpenKey.Call(prov, uintptr(unsafe.Pointer(&k)),
		uintptr(unsafe.Pointer(utf16(name))), 0, ncryptSilentFlag))
	return k, err
}

func ncryptCreateKey(prov uintptr, name string) (uintptr, error) {
	var k uintptr
	if err := ncryptStatus(procNCryptCreatePersistedKey.Call(prov, uintptr(unsafe.Pointer(&k)),
		uintptr(unsafe.Pointer(utf16("RSA"))), uintptr(unsafe.Pointer(utf16(name))), 0, 0)); err != nil {
		return 0, fmt.Errorf("NCryptCreatePersistedKey: %w", err)
	}
	bits := uint32(2048)
	if err := ncryptStatus(procNCryptSetProperty.Call(k, uintptr(unsafe.Pointer(utf16("Length"))),
		uintptr(unsafe.Pointer(&bits)), 4, 0)); err != nil {
		ncryptFree(k)
		return 0, fmt.Errorf("NCryptSetProperty(Length): %w", err)
	}
	if err := ncryptStatus(procNCryptFinalizeKey.Call(k, ncryptSilentFlag)); err != nil {
		ncryptFree(k)
		return 0, fmt.Errorf("NCryptFinalizeKey: %w", err)
	}
	return k, nil
}

// bcryptOAEPPaddingInfo is BCRYPT_OAEP_PADDING_INFO.
type bcryptOAEPPaddingInfo struct {
	algID   *uint16
	label   *byte
	labelSz uint32
}

// ncryptCrypt runs NCryptEncrypt or NCryptDecrypt with RSA-OAEP (SHA-256),
// first asking for the output size, then doing the work.
func ncryptCrypt(proc *windows.LazyProc, key uintptr, in []byte) ([]byte, error) {
	pad := bcryptOAEPPaddingInfo{algID: utf16("SHA256")}
	var n uint32
	call := func(out []byte) error {
		var outPtr uintptr
		if len(out) > 0 {
			outPtr = uintptr(unsafe.Pointer(&out[0]))
		}
		return ncryptStatus(proc.Call(key, uintptr(unsafe.Pointer(&in[0])), uintptr(len(in)),
			uintptr(unsafe.Pointer(&pad)), outPtr, uintptr(len(out)), uintptr(unsafe.Pointer(&n)),
			ncryptPadOAEPFlag|ncryptSilentFlag))
	}
	if len(in) == 0 {
		return nil, errors.New("empty input")
	}
	if err := call(nil); err != nil {
		return nil, err
	}
	out := make([]byte, n)
	if err := call(out); err != nil {
		return nil, err
	}
	return out[:n], nil
}

func ncryptFree(h uintptr) {
	if h != 0 {
		procNCryptFreeObject.Call(h)
	}
}
