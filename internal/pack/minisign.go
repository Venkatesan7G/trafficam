package pack

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// Signatures use the minisign format (https://jedisct1.github.io/minisign/),
// which is Ed25519 with a small text wrapper. Packs are signed with the
// ordinary `minisign` tool, so the secret key never touches this code.
//
// Only verification lives here. Both minisign algorithms are accepted:
//
//	"Ed": Ed25519 over the file itself (legacy, minisign -l)
//	"ED": Ed25519 over BLAKE2b-512 of the file (the default since 0.11)
//
// A minisign signature also signs a "trusted comment"; that comment is
// checked too (the "global signature"), and returned to the caller.

// PublicKey is a minisign Ed25519 public key.
type PublicKey struct {
	ID  [8]byte
	Key ed25519.PublicKey
}

// KeyID is the key id as minisign prints it (upper-case hex, byte-reversed).
func (k PublicKey) KeyID() string {
	var b strings.Builder
	for i := len(k.ID) - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "%02X", k.ID[i])
	}
	return b.String()
}

// ParsePublicKey reads a minisign public key: either the bare base64 line
// ("RW...") or the whole .pub file with its "untrusted comment:" line.
func ParsePublicKey(s string) (PublicKey, error) {
	var line string
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "untrusted comment:") {
			line = l
			break
		}
	}
	raw, err := base64.StdEncoding.DecodeString(line)
	if err != nil || len(raw) != 2+8+32 || string(raw[:2]) != "Ed" {
		return PublicKey{}, errors.New("pack: not a minisign Ed25519 public key")
	}
	var k PublicKey
	copy(k.ID[:], raw[2:10])
	k.Key = ed25519.PublicKey(append([]byte(nil), raw[10:]...))
	return k, nil
}

// Signature is a parsed .minisig file.
type Signature struct {
	Algorithm      string // "Ed" or "ED"
	KeyID          [8]byte
	Sig            []byte // 64 bytes
	TrustedComment string
	GlobalSig      []byte // 64 bytes, over Sig || TrustedComment
}

// ParseSignature reads a .minisig file.
func ParseSignature(data []byte) (Signature, error) {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	if len(lines) < 4 || !strings.HasPrefix(lines[0], "untrusted comment:") {
		return Signature{}, errors.New("pack: malformed signature file")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil || len(raw) != 2+8+64 {
		return Signature{}, errors.New("pack: malformed signature line")
	}
	const tc = "trusted comment: "
	if !strings.HasPrefix(lines[2], tc) {
		return Signature{}, errors.New("pack: signature has no trusted comment")
	}
	global, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[3]))
	if err != nil || len(global) != 64 {
		return Signature{}, errors.New("pack: malformed global signature")
	}
	s := Signature{Algorithm: string(raw[:2]), Sig: raw[10:], TrustedComment: lines[2][len(tc):], GlobalSig: global}
	copy(s.KeyID[:], raw[2:10])
	return s, nil
}

// ErrBadSignature means the signature does not match, or was made by a key
// this build does not trust.
var ErrBadSignature = errors.New("pack: signature is not valid for any trusted key")

// Verify checks msg against sig with the first of keys whose id matches.
// It returns the key that verified.
func Verify(keys []PublicKey, msg []byte, sig Signature) (PublicKey, error) {
	var signed []byte
	switch sig.Algorithm {
	case "ED":
		h := blake2b.Sum512(msg)
		signed = h[:]
	case "Ed":
		signed = msg
	default:
		return PublicKey{}, fmt.Errorf("%w: unknown algorithm %q", ErrBadSignature, sig.Algorithm)
	}
	for _, k := range keys {
		if !bytes.Equal(k.ID[:], sig.KeyID[:]) {
			continue
		}
		if !ed25519.Verify(k.Key, signed, sig.Sig) {
			return PublicKey{}, fmt.Errorf("%w: content does not match the signature (modified?)", ErrBadSignature)
		}
		global := append(append([]byte(nil), sig.Sig...), sig.TrustedComment...)
		if !ed25519.Verify(k.Key, global, sig.GlobalSig) {
			return PublicKey{}, fmt.Errorf("%w: trusted comment was modified", ErrBadSignature)
		}
		return k, nil
	}
	return PublicKey{}, fmt.Errorf("%w: signed by unknown key %s", ErrBadSignature, PublicKey{ID: sig.KeyID}.KeyID())
}
