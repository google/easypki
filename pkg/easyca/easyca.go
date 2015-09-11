package easyca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"time"
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

	privateKeyPath := filepath.Join(pkiroot, "private", name+".key")
	crtPath := filepath.Join(pkiroot, name+".crt")

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
		serialNumber, err := NextSerial(pkiroot)
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

func WriteIndex(pkiroot, filename string, crt *x509.Certificate) error {
	f, err := os.OpenFile(filepath.Join(pkiroot, "index.txt"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
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
	n, err := fmt.Fprintf(f, "V\t%vZ\t\t%v\t%v.crt\t%v\n",
		crt.NotAfter.UTC().Format("060102150405"),
		serialOutput,
		filename,
		"/CN="+crt.Subject.CommonName)
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("written 0 bytes in index file")
	}
	return nil
}
