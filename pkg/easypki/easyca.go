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

package easypki

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	// Index format
	// 0 full string
	// 1 Valid/Revoked/Expired
	// 2 Expiration date
	// 3 Revocation date
	// 4 Serial
	// 5 Filename
	// 6 Subject
	indexRegexp = regexp.MustCompile("^(V|R|E)\t([0-9]{12}Z)\t([0-9]{12}Z)?\t([0-9a-fA-F]{2,})\t([^\t]+)\t(.+)")
)

func GeneratePrivateKey(path string) (*rsa.PrivateKey, error) {
	keyFile, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create %v: %v", path, err)
	}
	defer keyFile.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate private key: %v", err)
	}
	err = pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err != nil {
		return nil, fmt.Errorf("pem encode private key: %v", err)
	}
	return key, nil
}

func GenerateCertifcate(pkiroot, name string, template *x509.Certificate) error {
	// TODO(jclerc): check that pki has been init

	var crtPath string
	privateKeyPath := filepath.Join(pkiroot, "private", name+".key")
	if name == "ca" {
		crtPath = filepath.Join(pkiroot, name+".crt")
	} else {
		crtPath = filepath.Join(pkiroot, "issued", name+".crt")
	}

	var caCrt *x509.Certificate
	var caKey *rsa.PrivateKey

	if _, err := os.Stat(privateKeyPath); err == nil {
		return fmt.Errorf("a key pair for %v already exists", name)
	}

	privateKey, err := GeneratePrivateKey(privateKeyPath)
	if err != nil {
		return fmt.Errorf("generate private key: %v", err)
	}

	publicKeyBytes, err := asn1.Marshal(*privateKey.Public().(*rsa.PublicKey))
	if err != nil {
		return fmt.Errorf("marshal public key: %v", err)
	}
	subjectKeyId := sha1.Sum(publicKeyBytes)
	template.SubjectKeyId = subjectKeyId[:]

	template.NotBefore = time.Now()
	template.SignatureAlgorithm = x509.SHA256WithRSA
	if template.IsCA {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return fmt.Errorf("failed to generate ca serial number: %s", err)
		}
		template.SerialNumber = serialNumber
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.BasicConstraintsValid = true
		template.Issuer = template.Subject
		template.AuthorityKeyId = template.SubjectKeyId

		caCrt = template
		caKey = privateKey
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		serialNumber, err := NextNumber(pkiroot, "serial")
		if err != nil {
			return fmt.Errorf("get next serial: %v", err)
		}
		template.SerialNumber = serialNumber

		caCrt, caKey, err = GetCA(pkiroot)
		if err != nil {
			return fmt.Errorf("get ca: %v", err)
		}
	}

	crt, err := x509.CreateCertificate(rand.Reader, template, caCrt, privateKey.Public(), caKey)
	if err != nil {
		return fmt.Errorf("create certificate: %v", err)
	}

	crtFile, err := os.Create(crtPath)
	if err != nil {
		return fmt.Errorf("create %v: %v", crtPath, err)
	}
	defer crtFile.Close()

	err = pem.Encode(crtFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crt,
	})
	if err != nil {
		return fmt.Errorf("pem encode crt: %v", err)
	}

	// I do not think we have to write the ca.crt in the index
	if !template.IsCA {
		WriteIndex(pkiroot, name, template)
		if err != nil {
			return fmt.Errorf("write index: %v", err)
		}
	}
	return nil
}

func GetCA(pkiroot string) (*x509.Certificate, *rsa.PrivateKey, error) {
	caKeyBytes, err := ioutil.ReadFile(filepath.Join(pkiroot, "private", "ca.key"))
	if err != nil {
		return nil, nil, fmt.Errorf("read ca private key: %v", err)
	}
	p, _ := pem.Decode(caKeyBytes)
	if p == nil {
		return nil, nil, fmt.Errorf("pem decode did not found pem encoded ca private key")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca private key: %v", err)
	}

	caCrtBytes, err := ioutil.ReadFile(filepath.Join(pkiroot, "ca.crt"))
	if err != nil {
		return nil, nil, fmt.Errorf("read ca crt: %v", err)
	}
	p, _ = pem.Decode(caCrtBytes)
	if p == nil {
		return nil, nil, fmt.Errorf("pem decode did not found pem encoded ca cert")
	}
	caCrt, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca crt: %v", err)
	}

	return caCrt, caKey, nil
}

func GenCRL(pkiroot string, expire int) error {
	var revokedCerts []pkix.RevokedCertificate
	f, err := os.Open(filepath.Join(pkiroot, "index.txt"))
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		matches := indexRegexp.FindStringSubmatch(scanner.Text())
		if len(matches) != 7 {
			return fmt.Errorf("wrong line format %v elems: %v, %v", len(matches), matches, scanner.Text())
		}
		if matches[1] != "R" {
			continue
		}

		crt, err := GetCertificate(filepath.Join(pkiroot, "issued", matches[5]))
		if err != nil {
			return fmt.Errorf("get certificate %v: %v", matches[5], err)
		}

		matchedSerial := big.NewInt(0)
		fmt.Sscanf(matches[4], "%X", matchedSerial)
		if matchedSerial.Cmp(crt.SerialNumber) != 0 {
			return fmt.Errorf("serial in index does not match revoked certificate: %v", matches[0])
		}
		revocationTime, err := time.Parse("060102150405", strings.TrimSuffix(matches[3], "Z"))
		if err != nil {
			return fmt.Errorf("parse revocation time: %v", err)
		}
		revokedCerts = append(revokedCerts, pkix.RevokedCertificate{
			SerialNumber:   crt.SerialNumber,
			RevocationTime: revocationTime,
			Extensions:     crt.Extensions,
		})
	}
	caCrt, caKey, err := GetCA(pkiroot)
	if err != nil {
		return fmt.Errorf("get ca: %v", err)
	}
	crl, err := caCrt.CreateCRL(rand.Reader, caKey, revokedCerts, time.Now(), time.Now().AddDate(0, 0, expire))
	if err != nil {
		return fmt.Errorf("create crl: %v", err)
	}
	// I do no see where we can pass it to CreateCRL, differs from openssl
	crlNumber, err := NextNumber(pkiroot, "crlnumber")
	if err != nil {
		return fmt.Errorf("get next serial: %v", err)
	}

	serialHexa := fmt.Sprintf("%X", crlNumber)
	if len(serialHexa)%2 == 1 {
		serialHexa = "0" + serialHexa
	}

	crlPath := filepath.Join(pkiroot, "crl-"+serialHexa+".pem")
	crlFile, err := os.Create(crlPath)
	if err != nil {
		return fmt.Errorf("create %v: %v", crlPath, err)
	}
	defer crlFile.Close()

	err = pem.Encode(crlFile, &pem.Block{
		Type:  "X509 CRL",
		Bytes: crl,
	})
	if err != nil {
		return fmt.Errorf("pem encode crt: %v", err)
	}

	return nil
}

func RevokeSerial(pkiroot string, serial *big.Int) error {
	f, err := os.OpenFile(filepath.Join(pkiroot, "index.txt"), os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		matches := indexRegexp.FindStringSubmatch(scanner.Text())
		if len(matches) != 7 {
			return fmt.Errorf("wrong line format")
		}
		matchedSerial := big.NewInt(0)
		fmt.Sscanf(matches[4], "%X", matchedSerial)
		if matchedSerial.Cmp(serial) == 0 {
			if matches[1] == "R" {
				return fmt.Errorf("certificate already revoked")
			} else if matches[1] == "E" {
				return fmt.Errorf("certificate already expired")
			}

			lines = append(lines, fmt.Sprintf("R\t%v\t%vZ\t%v\t%v\t%v",
				matches[2],
				time.Now().UTC().Format("060102150405"),
				matches[4],
				matches[5],
				matches[6]))
		} else {
			lines = append(lines, matches[0])
		}
	}

	f.Truncate(0)
	f.Seek(0, 0)

	for _, line := range lines {
		n, err := fmt.Fprintln(f, line)
		if err != nil {
			return fmt.Errorf("write line: %v", err)
		}
		if n == 0 {
			return fmt.Errorf("supposed to write [%v], written 0 bytes", line)
		}
	}
	return nil
}

func GetCertificate(path string) (*x509.Certificate, error) {
	crtBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read crt: %v", err)
	}
	p, _ := pem.Decode(crtBytes)
	if p == nil {
		return nil, fmt.Errorf("pem decode did not found pem encoded cert")
	}
	crt, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse crt: %v", err)
	}

	return crt, nil
}

func WriteIndex(pkiroot, filename string, crt *x509.Certificate) error {
	f, err := os.OpenFile(filepath.Join(pkiroot, "index.txt"), os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	serialOutput := fmt.Sprintf("%X", crt.SerialNumber)
	// For compatibility with openssl we need an even length
	if len(serialOutput)%2 == 1 {
		serialOutput = "0" + serialOutput
	}

	// Date format: yymmddHHMMSSZ
	// E|R|V<tab>Expiry<tab>[RevocationDate]<tab>Serial<tab>filename<tab>SubjectDN
	var subject string
	if strs := crt.Subject.Country; len(strs) == 1 {
		subject += "/C=" + strs[0]
	}
	if strs := crt.Subject.Organization; len(strs) == 1 {
		subject += "/O=" + strs[0]
	}
	if strs := crt.Subject.OrganizationalUnit; len(strs) == 1 {
		subject += "/OU=" + strs[0]
	}
	if strs := crt.Subject.Locality; len(strs) == 1 {
		subject += "/L=" + strs[0]
	}
	if strs := crt.Subject.Province; len(strs) == 1 {
		subject += "/ST=" + strs[0]
	}
	subject += "/CN=" + crt.Subject.CommonName

	n, err := fmt.Fprintf(f, "V\t%vZ\t\t%v\t%v.crt\t%v\n",
		crt.NotAfter.UTC().Format("060102150405"),
		serialOutput,
		filename,
		subject)
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("written 0 bytes in index file")
	}
	return nil
}

// |-ca.crt
// |-crlnumber
// |-index.txt
// |-index.txt.attr
// |-serial
// |-issued/
//   |- name.crt
// |-private
//   |- ca.key
//   |- name.key
func GeneratePKIStructure(pkiroot string) error {

	for _, dir := range []string{"private", "issued"} {
		err := os.Mkdir(filepath.Join(pkiroot, dir), 0755)
		if err != nil {
			return fmt.Errorf("creating dir %v: %v", dir, err)
		}
	}

	files := []struct {
		Name    string
		Content string
		File    *os.File
	}{
		{Name: "serial", Content: "01"},
		{Name: "crlnumber", Content: "01"},
		{Name: "index.txt", Content: ""},
		{Name: "index.txt.attr", Content: "unique_subject = no"},
	}
	for _, f := range files {
		// if using := here i get needs identifier, hm ?, needs to declare err before
		var err error
		f.File, err = os.Create(filepath.Join(pkiroot, f.Name))
		if err != nil {
			return fmt.Errorf("create %v: %v", f.Name, err)
		}
		defer f.File.Close()

		if len(f.Content) == 0 {
			continue
		}

		n, err := fmt.Fprintln(f.File, f.Content)
		if err != nil {
			return fmt.Errorf("write %v: %v", f.Name, err)
		}
		if n == 0 {
			return fmt.Errorf("write %v, written 0 bytes", f.Name)
		}
	}

	return nil
}

func NextNumber(pkiroot, name string) (*big.Int, error) {
	serial := big.NewInt(0)

	f, err := os.OpenFile(filepath.Join(pkiroot, name), os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	n, err := fmt.Fscanf(f, "%X\n", serial)
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, fmt.Errorf("supposed to read 1 element, read: %v", n)
	}

	next := big.NewInt(1)
	next.Add(serial, next)
	output := fmt.Sprintf("%X", next)
	// For compatibility with openssl we need an even length
	if len(output)%2 == 1 {
		output = "0" + output
	}
	f.Truncate(0)
	f.Seek(0, 0)

	n, err = fmt.Fprintln(f, output)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, fmt.Errorf("supposed to write 1 element, written: %v", n)
	}

	return serial, nil
}
