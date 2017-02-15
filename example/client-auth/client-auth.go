package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/boltdb/bolt"
	"github.com/go-yaml/yaml"
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
		configPath = flag.String("config_path", "", "Configuration path to generate PKI.")
	)
	flag.Parse()
	if *dbPath == "" {
		log.Fatal("Arg db_path must be set.")
	}
	if *bundleName == "" && *configPath == "" {
		log.Fatal("One of bundle_name or config_path must be set.")
	}
	db, err := bolt.Open(*dbPath, 0600, nil)
	if err != nil {
		log.Fatalf("Failed opening bolt database %v: %v", *dbPath, err)
	}
	defer db.Close()
	pki := &easypki.EasyPKI{Store: &store.Bolt{DB: db}}
	if *bundleName != "" {
		get(pki, *caName, *bundleName, *fullChain)
		return
	}
	build(pki, *configPath)
}

// build create a full PKI based on a yaml configuration.
func build(pki *easypki.EasyPKI, configPath string) {
	type configCerts struct {
		Name           string        `yaml:"name"`
		CommonName     string        `yaml:"commonName"`
		DNSNames       []string      `yaml:"dnsNames"`
		EmailAddresses []string      `yaml:"emailAddresses"`
		IsCA           bool          `yaml:"isCA"`
		IsClient       bool          `yaml:"isClient"`
		Signer         string        `yaml:"signer"`
		Expire         time.Duration `yaml:"expire"`
	}

	type config struct {
		Subject pkix.Name     `yaml:"subject"`
		Certs   []configCerts `yaml:"certs"`
	}

	b, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Failed reading configuration file %v: %v", configPath, err)
	}
	conf := &config{}
	if err := yaml.Unmarshal(b, conf); err != nil {
		log.Fatalf("Failed umarshaling yaml config (%v) %v: %v", configPath, string(b), err)
	}
	for _, cert := range conf.Certs {
		req := &easypki.Request{
			Name: cert.Name,
			Template: &x509.Certificate{
				Subject:        conf.Subject,
				NotAfter:       time.Now().Add(cert.Expire),
				IsCA:           cert.IsCA,
				DNSNames:       cert.DNSNames,
				EmailAddresses: cert.EmailAddresses,
			},
			IsClientCertificate: cert.IsClient,
		}
		if cert.IsCA {
			req.Template.MaxPathLen = -1
		}
		req.Template.Subject.CommonName = cert.CommonName
		var signer *certificate.Bundle
		if cert.Signer != "" {
			signer, err = pki.GetCA(cert.Signer)
			if err != nil {
				log.Fatalf("Cannot sign %v because cannot get CA %v: %v", cert.Name, cert.Signer, err)
			}
		}
		if err := pki.Sign(signer, req); err != nil {
			log.Fatalf("Cannot create bundle for %v: %v", cert.Name, err)
		}
	}
}

// get retrieves a bundle from the bolt database. If fullChain is true, the
// certificate will be the chain of trust from the primary tup to root CA.
func get(pki *easypki.EasyPKI, caName, bundleName string, fullChain bool) {
	var bundle *certificate.Bundle
	if caName == "" {
		caName = bundleName
	}
	bundle, err := pki.GetBundle(caName, bundleName)
	if err != nil {
		log.Fatalf("Failed getting bundle %v within CA %v: %v", bundleName, caName, err)
	}
	leaf := bundle
	chain := []*certificate.Bundle{bundle}
	if fullChain {
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
	key, err := os.Create(bundleName + ".key")
	if err != nil {
		log.Fatalf("Failed creating key output file: %v", err)
	}
	if err := pem.Encode(key, &pem.Block{
		Bytes: x509.MarshalPKCS1PrivateKey(bundle.Key),
		Type:  "RSA PRIVATE KEY",
	}); err != nil {
		log.Fatalf("Failed ecoding private key: %v", err)
	}
	crtName := bundleName + ".crt"
	if fullChain {
		crtName = bundleName + "+chain.crt"
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
