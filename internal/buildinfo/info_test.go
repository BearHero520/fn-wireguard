package buildinfo

import (
	"os"
	"strings"
	"testing"
)

func TestManifestIdentityMatchesApplication(t *testing.T) {
	manifest, err := os.ReadFile("../../packaging/fnos/manifest")
	if err != nil {
		t.Fatal(err)
	}
	text := "\n" + strings.ReplaceAll(string(manifest), "\r\n", "\n")
	for _, line := range []string{"version=" + Version, "maintainer=" + Author, "distributor=" + Author} {
		if !strings.Contains(text, "\n"+line+"\n") {
			t.Fatal("package metadata differs from application", line)
		}
	}
}
