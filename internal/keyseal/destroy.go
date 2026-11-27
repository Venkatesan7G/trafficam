package keyseal

import (
	"crypto/rand"
	"errors"
	"os"
)

// KeyDeleter is implemented by sealers that keep something of their own
// outside the key file (the Windows TPM key). Destroy calls it.
type KeyDeleter interface {
	DeleteKey() error
}

// Destroy makes the current database key unrecoverable: the key file is
// overwritten with random bytes, flushed and removed. Because the key only
// ever existed sealed, the encrypted database cannot be opened afterwards.
//
// Limit: on SSDs and copy-on-write file systems an overwrite may not reach
// the old blocks. That is acceptable because those blocks hold the *sealed*
// key, which is useless without this PC's TPM / account / machine id.
//
// The TPM key behind windows-tpm is shared with the next key, so it is not
// deleted here (see DeleteTPMKeys).
func (p *Sealed) Destroy() error {
	f, err := os.OpenFile(p.Path, os.O_WRONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err == nil {
		if st, serr := f.Stat(); serr == nil && st.Size() > 0 {
			junk := make([]byte, st.Size())
			_, _ = rand.Read(junk)
			_, _ = f.WriteAt(junk, 0)
			_ = f.Sync()
		}
		f.Close()
	}
	if err := os.Remove(p.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// DeleteTPMKeys removes TPM-resident keys of every sealer that has one. The
// next Key() call creates fresh ones.
func (p *Sealed) DeleteTPMKeys() error {
	var errs []error
	for _, s := range p.Sealers {
		if d, ok := s.(KeyDeleter); ok {
			errs = append(errs, d.DeleteKey())
		}
	}
	return errors.Join(errs...)
}
