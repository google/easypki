package main

import (
	"encoding/pem"
	"flag"
	"log"

	"os"

	"crypto/x509"

	"github.com/boltdb/bolt"
	"github.com/google/easypki/pkg/certificate"
	"github.com/google/easypki/pkg/easypki"
	"github.com/google/easypki/pkg/store"
)

func main() {
	var (
		caName     = flag.String("ca_name", "", "Name of the CA which signed the bundle.")
		bundleName = flag.String("bundle_name", "", "Name of the bundle to retrieve.")
		fullChain  = flag.Bool("full_chain", true, "Include chain of trust in certificate output.")
		dbPath     = flag.String("db_path", "", "Bolt database path.")
	)
	flag.Parse()
	if *bundleName == "" {
		log.Fatal("bundle_name cannot be empty")
	}
	db, err := bolt.Open(*dbPath, 0600, nil)
	if err != nil {
		log.Fatalf("Failed opening bolt database %v: %v", *dbPath, err)
	}
	defer db.Close()
	pki := &easypki.EasyPKI{Store: &store.Bolt{DB: db}}

	var bundle *certificate.Bundle
	if *caName == "" {
		*caName = *bundleName
	}
	bundle, err = pki.GetBundle(*caName, *bundleName)
	if err != nil {
		log.Fatalf("Failed getting bundle %v within CA %v: %v", *bundleName, *caName, err)
	}
	leaf := bundle
	chain := []*certificate.Bundle{bundle}
	if *fullChain {
		for {
			if leaf.Cert.Issuer.CommonName == leaf.Cert.Subject.CommonName {
				break
			}
			ca, err := pki.GetCA(leaf.Cert.Issuer.CommonName)
			if err != nil {
				log.Fatalf("Failed getting signing CA %v: %v", leaf.Cert.Issuer.CommonName, err)
			}
			chain = append(chain, ca)
			leaf = ca
		}
	}
	key, err := os.Create(*bundleName + ".key")
	if err != nil {
		log.Fatalf("Failed creating key output file: %v", err)
	}
	if err := pem.Encode(key, &pem.Block{
		Bytes: x509.MarshalPKCS1PrivateKey(bundle.Key),
		Type:  "RSA PRIVATE KEY",
	}); err != nil {
		log.Fatalf("Failed ecoding private key: %v", err)
	}
	crtName := *bundleName + ".crt"
	if *fullChain {
		crtName = *bundleName + "+chain.crt"
	}
	cert, err := os.Create(crtName)
	if err != nil {
		log.Fatalf("Failed creating chain output file: %v", err)
	}
	for _, c := range chain {
		if err := pem.Encode(cert, &pem.Block{
			Bytes: c.Cert.Raw,
			Type:  "CERTIFICATE",
		}); err != nil {
			log.Fatalf("Failed ecoding %v certificate: %v", c.Name, err)
		}
	}
}
