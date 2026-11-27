//go:build windows && (amd64 || arm64)

package etw

// Who signed this .exe? Windows programs are signed in one of two ways:
//
//  1. Embedded: the signature is inside the file (most third-party apps).
//  2. Catalog:  the file's hash is listed in a signed .cat file under
//     C:\Windows\System32\CatRoot (most of Windows itself, e.g. svchost.exe).
//
// WinVerifyTrust checks either kind. We try embedded first, then look the
// file's hash up in the catalogs. Revocation checks are switched off and URL
// retrieval is cache-only, so checking a signature never makes a network
// call: trafficam stays fully offline.
//
// Results (stored in event.Program.Signer):
//
//	"Microsoft Windows", "Google LLC", ...  valid signature, signer's name
//	"untrusted:<name>"                      signed, but the check failed (tampered, expired root, ...)
//	"unsigned"                              no signature at all
//	""                                      could not check (file unreadable)

import (
	"encoding/hex"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wintrust                                 = windows.NewLazySystemDLL("wintrust.dll")
	procCryptCATAdminAcquireContext2         = wintrust.NewProc("CryptCATAdminAcquireContext2")
	procCryptCATAdminReleaseContext          = wintrust.NewProc("CryptCATAdminReleaseContext")
	procCryptCATAdminCalcHashFromFileHandle2 = wintrust.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	procCryptCATAdminEnumCatalogFromHash     = wintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCryptCATAdminReleaseCatalogContext   = wintrust.NewProc("CryptCATAdminReleaseCatalogContext")
	procCryptCATCatalogInfoFromContext       = wintrust.NewProc("CryptCATCatalogInfoFromContext")
	procWTHelperProvDataFromStateData        = wintrust.NewProc("WTHelperProvDataFromStateData")
	procWTHelperGetProvSignerFromChain       = wintrust.NewProc("WTHelperGetProvSignerFromChain")
	procWTHelperGetProvCertFromChain         = wintrust.NewProc("WTHelperGetProvCertFromChain")
)

const (
	trustENoSignature        = 0x800B0100
	trustESubjectFormUnknown = 0x800B0003
	trustEProviderUnknown    = 0x800B0001
	certNameSimpleDisplay    = 4
)

// wintrustCatalogInfo is WINTRUST_CATALOG_INFO (72 bytes on 64-bit).
type wintrustCatalogInfo struct {
	Size                 uint32
	CatalogVersion       uint32
	CatalogFilePath      *uint16
	MemberTag            *uint16
	MemberFilePath       *uint16
	MemberFile           windows.Handle
	CalculatedFileHash   *byte
	CalculatedFileHashSz uint32
	CatalogContext       uintptr
	CatAdmin             windows.Handle
}

// catalogInfo is CATALOG_INFO.
type catalogInfo struct {
	Size        uint32
	CatalogFile [windows.MAX_PATH]uint16
}

type signerCache struct {
	mu sync.Mutex
	m  map[string]signerEntry
}

type signerEntry struct {
	mod    time.Time
	size   int64
	signer string
}

func newSignerCache() *signerCache { return &signerCache{m: map[string]signerEntry{}} }

// signer returns the cached signer for path, checking again if the file changed.
func (c *signerCache) signer(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return ""
	}
	key := strings.ToLower(path)
	c.mu.Lock()
	e, ok := c.m[key]
	c.mu.Unlock()
	if ok && e.mod.Equal(st.ModTime()) && e.size == st.Size() {
		return e.signer
	}
	s := verifySigner(path)
	c.mu.Lock()
	if len(c.m) > 10_000 {
		c.m = map[string]signerEntry{} // bound memory
	}
	c.m[key] = signerEntry{mod: st.ModTime(), size: st.Size(), signer: s}
	c.mu.Unlock()
	return s
}

func verifySigner(path string) string {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	fi := &windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: p}
	name, code := winVerify(windows.WTD_CHOICE_FILE, unsafe.Pointer(fi))
	switch {
	case code == 0:
		return name
	case code == trustENoSignature || code == trustESubjectFormUnknown || code == trustEProviderUnknown:
		// Not signed inside the file: try the Windows catalogs.
		if name, code, found := verifyCatalog(path, p); found {
			if code == 0 {
				return name
			}
			return "untrusted:" + name
		}
		return "unsigned"
	default:
		return "untrusted:" + name
	}
}

// winVerify runs WinVerifyTrust and, whatever the verdict, returns the
// signer's display name if Windows could read one.
func winVerify(choice uint32, info unsafe.Pointer) (name string, code uint32) {
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     choice,
		FileOrCatalogOrBlobOrSgnrOrCert: info,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       windows.WTD_REVOCATION_CHECK_NONE | windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
	}
	err := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if err != nil {
		if e, ok := err.(syscall.Errno); ok {
			code = uint32(e)
		} else {
			code = 1
		}
	}
	name = signerName(data.StateData)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	return name, code
}

// signerName digs the leaf certificate's display name out of WinVerifyTrust's state.
func signerName(state windows.Handle) string {
	if state == 0 {
		return ""
	}
	prov, _, _ := procWTHelperProvDataFromStateData.Call(uintptr(state))
	if prov == 0 {
		return ""
	}
	sgnr, _, _ := procWTHelperGetProvSignerFromChain.Call(prov, 0, 0, 0)
	if sgnr == 0 {
		return ""
	}
	pc, _, _ := procWTHelperGetProvCertFromChain.Call(sgnr, 0)
	if pc == 0 {
		return ""
	}
	// CRYPT_PROVIDER_CERT starts with cbStruct (DWORD, padded to 8) then pCert.
	// (Reinterpreting the returned address this way keeps "go vet" happy.)
	pcPtr := *(*unsafe.Pointer)(unsafe.Pointer(&pc))
	cert := *(**windows.CertContext)(unsafe.Add(pcPtr, 8))
	if cert == nil {
		return ""
	}
	buf := make([]uint16, 256)
	n := windows.CertGetNameString(cert, certNameSimpleDisplay, 0, nil, &buf[0], uint32(len(buf)))
	if n <= 1 {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// verifyCatalog looks the file's hash up in the system catalogs. found is
// false if no catalog lists the file.
func verifyCatalog(path string, p *uint16) (name string, code uint32, found bool) {
	f, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return "", 0, false
	}
	defer windows.CloseHandle(f)

	for _, alg := range []string{"SHA256", "SHA1"} {
		algPtr, _ := windows.UTF16PtrFromString(alg)
		var admin windows.Handle
		if r, _, _ := procCryptCATAdminAcquireContext2.Call(uintptr(unsafe.Pointer(&admin)), 0, uintptr(unsafe.Pointer(algPtr)), 0, 0); r == 0 {
			continue
		}
		name, code, found = func() (string, uint32, bool) {
			defer procCryptCATAdminReleaseContext.Call(uintptr(admin), 0)
			hash := make([]byte, 64)
			n := uint32(len(hash))
			if r, _, _ := procCryptCATAdminCalcHashFromFileHandle2.Call(uintptr(admin), uintptr(f), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&hash[0])), 0); r == 0 {
				return "", 0, false
			}
			hash = hash[:n]
			cat, _, _ := procCryptCATAdminEnumCatalogFromHash.Call(uintptr(admin), uintptr(unsafe.Pointer(&hash[0])), uintptr(n), 0, 0)
			if cat == 0 {
				return "", 0, false
			}
			defer procCryptCATAdminReleaseCatalogContext.Call(uintptr(admin), cat, 0)
			ci := &catalogInfo{Size: uint32(unsafe.Sizeof(catalogInfo{}))}
			if r, _, _ := procCryptCATCatalogInfoFromContext.Call(cat, uintptr(unsafe.Pointer(ci)), 0); r == 0 {
				return "", 0, false
			}
			tag, _ := windows.UTF16PtrFromString(strings.ToUpper(hex.EncodeToString(hash)))
			info := &wintrustCatalogInfo{
				Size:                 uint32(unsafe.Sizeof(wintrustCatalogInfo{})),
				CatalogFilePath:      &ci.CatalogFile[0],
				MemberTag:            tag,
				MemberFilePath:       p,
				MemberFile:           f,
				CalculatedFileHash:   &hash[0],
				CalculatedFileHashSz: n,
				CatAdmin:             admin,
			}
			nm, c := winVerify(windows.WTD_CHOICE_CATALOG, unsafe.Pointer(info))
			return nm, c, true
		}()
		if found {
			return name, code, true
		}
	}
	return "", 0, false
}
