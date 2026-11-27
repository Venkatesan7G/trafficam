package pack

import "fmt"

// releaseKeys are the minisign public keys allowed to sign knowledge packs.
// They are compiled in on purpose: a key that could be added at run time
// could also be added by malware.
//
// EMPTY UNTIL THE PROJECT OWNER CREATES THE RELEASE KEY. Until then no pack
// can be installed. To set it (docs/PACKS.md, "Creating the signing key"):
//
//	minisign -G -p trafficam-packs.pub -s ~/.minisign/trafficam-packs.key
//
// then paste the second line of trafficam-packs.pub below. Keep the secret
// key offline (a USB stick), never in the repository. To rotate, add the new
// key here, release, sign with the new key from then on, and remove the old
// key one release later.
var releaseKeys = []string{
	// "RW...",
}

// TrustedKeys returns the compiled-in signing keys.
func TrustedKeys() ([]PublicKey, error) {
	var out []PublicKey
	for _, s := range releaseKeys {
		k, err := ParsePublicKey(s)
		if err != nil {
			return nil, fmt.Errorf("pack: compiled-in key %q: %w", s, err)
		}
		out = append(out, k)
	}
	return out, nil
}
