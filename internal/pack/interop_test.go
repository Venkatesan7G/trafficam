package pack

import (
	"os"
	"testing"
)

// testdata/minisign-signed-pack.tar was built with trafficam-pack and signed
// with the real minisign tool (key testdata/test.pub; its secret key was
// thrown away). It proves the whole chain works with minisign itself.
func TestInstallPackSignedByRealMinisign(t *testing.T) {
	pubText, _ := os.ReadFile("testdata/test.pub")
	pub, err := ParsePublicKey(string(pubText))
	if err != nil {
		t.Fatal(err)
	}
	inst, err := Install("testdata/minisign-signed-pack.tar", t.TempDir(), []PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	if inst.Manifest.Seq != 1 || inst.Path(KindBlocklist) == "" || inst.Path(KindTrustedOS) == "" {
		t.Fatalf("installed: %+v", inst.Manifest)
	}
}
