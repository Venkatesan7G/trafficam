//go:build linux

package keyseal

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// LinuxTPMDevice is the kernel's TPM resource manager. The raw /dev/tpm0 is
// not used: talking to it directly would fight with other TPM users.
const LinuxTPMDevice = "/dev/tpmrm0"

// platformSealers on Linux: the TPM if there is one, else the machine id.
func platformSealers() []Sealer {
	return []Sealer{
		&TPM2{Name: "linux-tpm2", Open: func() (transport.TPMCloser, error) { return linuxtpm.Open(LinuxTPMDevice) }},
		&MachineID{},
	}
}
