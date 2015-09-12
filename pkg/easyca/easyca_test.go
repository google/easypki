package easyca

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TODO(jclerc): check correct error if structure already exists
// TODO(jclerc): check contents of files
func TestGeneratePKIStructure(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	pkiroot := filepath.Join(os.TempDir(), fmt.Sprintf("test-pki-%v", rand.Int63()))
	if err := os.Mkdir(pkiroot, 0755); err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	if err := GeneratePKIStructure(pkiroot); err != nil {
		t.Fatalf("%v", err)
	}

	// We should check the minimum content also..
	toCheck := []struct {
		Name string
		Dir  bool
	}{
		{"private", true},
		{"issued", true},
		{"serial", false},
		{"crlnumber", false},
		{"index.txt", false},
		{"index.txt.attr", false},
	}

	for _, name := range toCheck {
		fd, err := os.Stat(filepath.Join(pkiroot, name.Name))
		if err != nil {
			t.Errorf("%v: %v", name.Name, err)
		}
		if name.Dir && !fd.IsDir() {
			t.Errorf("%v supposed to be a directory", name.Name)
		}
	}
	if err := os.RemoveAll(pkiroot); err != nil {
		t.Logf("failed cleaning tmp dir %v: %v", pkiroot, err)
	}
}
