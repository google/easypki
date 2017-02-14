// Copyright 2017 Google Inc.
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

package easypki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"

	"github.com/boltdb/bolt"
	"github.com/google/easypki/pkg/store"

	"reflect"
)

func TestLocalE2E(t *testing.T) {
	root, err := ioutil.TempDir("", "testeasypki")
	if err != nil {
		t.Fatalf("failed creating temporary directory: %v", err)
	}
	defer os.RemoveAll(root)

	E2E(t, &EasyPKI{Store: &store.Local{Root: root}})
}

func TestBoltE2E(t *testing.T) {
	f, err := ioutil.TempFile("", "boltdb")
	if err != nil {
		t.Fatalf("failed creating tempfile for boltdb: %v", err)
	}
	defer os.Remove(f.Name())
	db, err := bolt.Open(f.Name(), 0600, nil)
	if err != nil {
		t.Fatalf("failed opening temp boltdb: %v", err)
	}
	defer db.Close()
	E2E(t, &EasyPKI{Store: &store.Bolt{DB: db}})
}

// E2E provides a frameweork to run tests end to end using a different
// store backend.
func E2E(t *testing.T, pki *EasyPKI) {
	commonSubject := pkix.Name{
		Organization:       []string{"Acme Inc."},
		OrganizationalUnit: []string{"IT"},
		Locality:           []string{"Agloe"},
		Country:            []string{"US"},
		Province:           []string{"New York"},
	}

	caRequest := &Request{
		Name: "Root_CA",
		Template: &x509.Certificate{
			Subject:    commonSubject,
			NotAfter:   time.Now().AddDate(0, 0, 30),
			MaxPathLen: 1,
			IsCA:       true,
		},
	}
	caRequest.Template.Subject.CommonName = "Root CA"
	if err := pki.Sign(nil, caRequest); err != nil {
		t.Fatalf("Sign(nil, %v): got error: %v != expected nil", caRequest, err)
	}
	rootCA, err := pki.GetCA(caRequest.Name)
	if err != nil {
		t.Fatalf("GetCA(%v): got error %v != expect nil", caRequest.Name, err)
	}

	cliRequest := &Request{
		Name: "bob@acme.org",
		Template: &x509.Certificate{
			Subject:        commonSubject,
			NotAfter:       time.Now().AddDate(0, 0, 30),
			EmailAddresses: []string{"bob@acme.org"},
		},
		IsClientCertificate: true,
	}
	cliRequest.Template.Subject.CommonName = "bob@acme.org"
	if err := pki.Sign(rootCA, cliRequest); err != nil {
		t.Fatalf("Sign(%v, %v): go error: %v != expected nil", rootCA, cliRequest, err)
	}
	cli, err := pki.GetBundle(caRequest.Name, cliRequest.Name)
	if err != nil {
		t.Fatalf("GetBundle(%v, %v): go error %v != expected nil", caRequest.Name, cliRequest.Name, err)
	}

	expectedExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if !reflect.DeepEqual(cli.Cert.ExtKeyUsage, expectedExtKeyUsage) {
		t.Errorf("Client ExtKeyUsage: got %v != expected %v", cli.Cert.ExtKeyUsage, expectedExtKeyUsage)
	}

	if err := pki.Sign(nil, cliRequest); err != ErrCannotSelfSignNonCA {
		t.Errorf("Sign(nil, %v): got error %v != expected %v", cliRequest, err, ErrCannotSelfSignNonCA)
	}

	intRequest := &Request{
		Name: "Intermediate_CA",
		Template: &x509.Certificate{
			Subject:  commonSubject,
			NotAfter: time.Now().AddDate(0, 0, 30),
			IsCA:     true,
		},
	}
	intRequest.Template.Subject.CommonName = "Intermediate CA"
	if err := pki.Sign(rootCA, intRequest); err != nil {
		t.Fatalf("Sign(%v, %v): go error: %v != expected nil", rootCA, intRequest, err)
	}
	intCA, err := pki.GetCA(intRequest.Name)
	if err != nil {
		t.Fatalf("GetCA(%v): got error %v != expect nil", intRequest.Name, err)
	}

	srvRequest := &Request{
		Name: "wiki.acme.org",
		Template: &x509.Certificate{
			Subject:     commonSubject,
			NotAfter:    time.Now().AddDate(0, 0, 30),
			DNSNames:    []string{"wiki.acme.org"},
			IPAddresses: []net.IP{net.ParseIP("10.10.10.10")},
		},
		PrivateKeySize: 4096,
	}
	srvRequest.Template.Subject.CommonName = "wiki.acme.org"
	if err := pki.Sign(intCA, srvRequest); err != nil {
		t.Fatalf("Sign(%v, %v): go error: %v != expected nil", intCA, srvRequest, err)

	}
	srv, err := pki.GetBundle(intRequest.Name, srvRequest.Name)
	if err != nil {
		t.Fatalf("GetBundle(%v, %v): go error %v != expected nil", intRequest.Name, srvRequest.Name, err)
	}

	if err := pki.Revoke(intRequest.Name, srv.Cert); err != nil {
		t.Fatalf("Revoke(%v, %v): got error: %v != expected nil", intRequest.Name, srv.Cert, err)
	}
	expire := time.Now().Add(time.Hour * 24)
	crlBytes, err := pki.CRL(intRequest.Name, expire)
	if err != nil {
		t.Fatalf("CRL(%v, %v): got error %v != expected nil", intRequest.Name, expire, err)
	}

	crl, err := x509.ParseCRL(crlBytes)
	if err != nil {
		t.Fatalf("ParseCRL(%v): got error %v != expected nil", crlBytes, err)
	}
	if len(crl.TBSCertList.RevokedCertificates) != 1 {
		t.Fatalf("CRL does not have 1 revoked certificate: %v", crl)
	}
	if srv.Cert.SerialNumber.Cmp(crl.TBSCertList.RevokedCertificates[0].SerialNumber) != 0 {
		t.Fatalf("Server certificate serial number %v != revoked server certificate serial %v",
			srv.Cert.SerialNumber, crl.TBSCertList.RevokedCertificates[0].SerialNumber)
	}

	tooDeepReq := &Request{
		Name: "Deep_Intermediate_CA",
		Template: &x509.Certificate{
			Subject:  commonSubject,
			NotAfter: time.Now().AddDate(0, 0, 30),
			IsCA:     true,
		},
	}
	tooDeepReq.Template.Subject.CommonName = "Deep Intermediate CA"
	if err := pki.Sign(intCA, tooDeepReq); err != ErrMaxPathLenReached {
		t.Errorf("Sign(%v, %v): got error %v != expected %v", intCA, tooDeepReq, err, ErrMaxPathLenReached)
	}
}
