//go:build !linux && !windows

package keyseal

// platformSealers on other systems (development only): the machine id.
func platformSealers() []Sealer { return []Sealer{&MachineID{}} }
