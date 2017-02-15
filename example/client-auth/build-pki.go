package main

import (
	"crypto/x509/pkix"
	"flag"
	"io/ioutil"
	"log"

	"crypto/x509"
	"time"

	"github.com/boltdb/bolt"
	"github.com/go-yaml/yaml"
	"github.com/google/easypki/pkg/certificate"
	"github.com/google/easypki/pkg/easypki"
	"github.com/google/easypki/pkg/store"
)

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

func main() {
	var (
		configPath = flag.String("config_path", "chain.yaml", "Configuration path to generate PKI.")
		dbPath     = flag.String("db_path", "", "Bolt database path.")
	)
	flag.Parse()
	b, err := ioutil.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("Failed reading configuration file %v: %v", *configPath, err)
	}
	conf := &config{}
	if err := yaml.Unmarshal(b, conf); err != nil {
		log.Fatalf("Failed umarshaling yaml config (%v) %v: %v", *configPath, string(b), err)
	}
	db, err := bolt.Open(*dbPath, 0600, nil)
	if err != nil {
		log.Fatalf("Failed opening bolt database %v: %v", *dbPath, err)
	}
	defer db.Close()
	pki := &easypki.EasyPKI{Store: &store.Bolt{DB: db}}
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
