// Copyright 2015 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package easyca

import (
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGeneratePKIStructure(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	pkiroot, err := ioutil.TempDir("", "gotestpki")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	if err := GeneratePKIStructure(pkiroot); err != nil {
		t.Fatalf("%v", err)
	}

	// We should check the minimum content also..
	toCheck := []struct {
		Name    string
		Dir     bool
		Content string
	}{
		{"private", true, ""},
		{"issued", true, ""},
		{"serial", false, "01\n"},
		{"crlnumber", false, "01\n"},
		{"index.txt", false, ""},
		{"index.txt.attr", false, "unique_subject = no\n"},
	}

	for _, name := range toCheck {
		fd, err := os.Stat(filepath.Join(pkiroot, name.Name))
		if err != nil {
			t.Errorf("%v: %v", name.Name, err)
		}
		if name.Dir && !fd.IsDir() {
			t.Errorf("%v supposed to be a directory", name.Name)
		}
		if len(name.Content) > 0 {
			f, err := os.Open(filepath.Join(pkiroot, name.Name))
			if err != nil {
				t.Fatalf("failed open %v: %v", name.Name, err)
			}
			defer f.Close()
			bytes, err := ioutil.ReadAll(f)
			if err != nil {
				t.Fatalf("failed read %v: %v", name.Name, err)
			}
			if string(bytes) != name.Content {
				t.Fatalf("%v content expected %v, got: %v", name.Name, name.Content, string(bytes))
			}
		}
	}
	if err := os.RemoveAll(pkiroot); err != nil {
		t.Logf("failed cleaning tmp dir %v: %v", pkiroot, err)
	}
}

func TestNextNumber(t *testing.T) {
	pkiroot, err := ioutil.TempDir("", "gotestpki")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	if err := GeneratePKIStructure(pkiroot); err != nil {
		t.Fatalf("generate pki structure: %v", err)
	}

	n, err := NextNumber(pkiroot, "serial")
	if err != nil {
		t.Fatal("failed get next serial number: %v", err)
	}
	if big.NewInt(1).Cmp(n) != 0 {
		t.Fatalf("after init serial is supposed to be 1, value is: %v", n)
	}
	// File content is now 02
	f, err := os.Open(filepath.Join(pkiroot, "serial"))
	if err != nil {
		t.Fatalf("failed open serial: %v", err)
	}
	defer f.Close()
	bytes, err := ioutil.ReadAll(f)
	if err != nil {
		t.Fatalf("failed read serial: %v", err)
	}
	if string(bytes) != "02\n" {
		t.Fatalf("serial content expected 02, got: %v", string(bytes))
	}
}

func TestLargeNextNumber(t *testing.T) {
	pkiroot, err := ioutil.TempDir("", "gotestpki")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	if err := GeneratePKIStructure(pkiroot); err != nil {
		t.Fatalf("generate pki structure: %v", err)
	}

	for {
		n, err := NextNumber(pkiroot, "serial")
		if err != nil {
			t.Fatal("failed get next serial number: %v", err)
		}
		if big.NewInt(255).Cmp(n) == 0 {
			break
		}
	}
	f, err := os.Open(filepath.Join(pkiroot, "serial"))
	if err != nil {
		t.Fatalf("failed open serial: %v", err)
	}
	defer f.Close()
	bytes, err := ioutil.ReadAll(f)
	if err != nil {
		t.Fatalf("failed read serial: %v", err)
	}
	if string(bytes) != "0100\n" {
		t.Fatalf("serial content expected 0100, got: %v", string(bytes))
	}
}
