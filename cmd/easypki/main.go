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

package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/codegangsta/cli"
	"github.com/jeremy-clerc/easypki/pkg/easypki"
)

// https://access.redhat.com/documentation/en-US/Red_Hat_Certificate_System/8.0/html/Admin_Guide/Standard_X.509_v3_Certificate_Extensions.html
// B.3.8. keyUsage

func initPki(c *cli.Context) {
	log.Print("generating new pki structure")
	if err := easypki.GeneratePKIStructure(c.GlobalString("root")); err != nil {
		log.Fatalf("generate pki structure: %v", err)
	}
}

func createBundle(c *cli.Context) {
	if !c.Args().Present() {
		cli.ShowSubcommandHelp(c)
		log.Fatalf("Usage: %v name (common name defaults to name, use --cn and "+
			"different name if you need multiple certs for same cn)", c.Command.FullName())
	}

	commonName := strings.Join(c.Args()[:], " ")
	var filename string
	if filename = c.String("filename"); len(filename) == 0 {
		filename = strings.Replace(commonName, " ", "_", -1)
		filename = strings.Replace(filename, "*", "wildcard", -1)
	}

	subject := pkix.Name{CommonName: commonName}
	if str := c.String("organization"); len(str) > 0 {
		subject.Organization = []string{str}
	}
	if str := c.String("locality"); len(str) > 0 {
		subject.Locality = []string{str}
	}
	if str := c.String("country"); len(str) > 0 {
		subject.Country = []string{str}
	}
	if str := c.String("province"); len(str) > 0 {
		subject.Province = []string{str}
	}
	if str := c.String("organizational-unit"); len(str) > 0 {
		subject.OrganizationalUnit = []string{str}
	}

	template := &x509.Certificate{
		Subject:  subject,
		NotAfter: time.Now().AddDate(0, 0, c.Int("expire")),
	}

	if c.Bool("ca") {
		template.IsCA = true
		filename = "ca"
	} else if c.Bool("client") {
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
		template.EmailAddresses = c.StringSlice("email")
	} else {
		// We default to server
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)

		IPs := make([]net.IP, 0, len(c.StringSlice("ip")))
		for _, ipStr := range c.StringSlice("ip") {
			if i := net.ParseIP(ipStr); i != nil {
				IPs = append(IPs, i)
			}
		}
		template.IPAddresses = IPs
		template.DNSNames = c.StringSlice("dns")
	}
	err := easypki.GenerateCertifcate(c.GlobalString("root"), filename, template)
	if err != nil {
		log.Fatal(err)
	}
}
func revoke(c *cli.Context) {
	if !c.Args().Present() {
		cli.ShowSubcommandHelp(c)
		log.Fatalf("Usage: %v path/to/cert.crt", c.Command.FullName())
	}
	crtPath := c.Args().First()
	crt, err := easypki.GetCertificate(crtPath)
	if err != nil {
		log.Fatalf("get certificate (%v): %v", crtPath, err)
	}
	err = easypki.RevokeSerial(c.GlobalString("root"), crt.SerialNumber)
	if err != nil {
		log.Fatalf("revoke serial %X: %v", crt.SerialNumber, err)
	}
}

func gencrl(c *cli.Context) {
	if err := easypki.GenCRL(c.GlobalString("root"), c.Int("expire")); err != nil {
		log.Fatalf("general crl: %v", err)
	}
}

func parseArgs() {
	app := cli.NewApp()
	app.Name = "easypki"
	app.Usage = "Manage pki"
	app.Author = "Jeremy Clerc"
	app.Email = "jeremy@clerc.io"
	app.Version = "0.0.1"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "root",
			Value:  filepath.Join(os.Getenv("PWD"), "pki_auto_generated_dir"),
			Usage:  "path to pki root directory",
			EnvVar: "PKI_ROOT",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:        "init",
			Description: "create directory structure",
			Action:      initPki,
		},
		{
			Name:        "revoke",
			Usage:       "revoke path/to/cert",
			Description: "revoke certificate",
			Action:      revoke,
		},
		{
			Name:        "gencrl",
			Description: "generate certificate revocation list",
			Action:      gencrl,
			Flags: []cli.Flag{
				cli.IntFlag{
					Name:  "expire",
					Usage: "expiration limit in days",
					Value: 30,
				},
			},
		},
		{
			Name:        "create",
			Usage:       "create COMMON NAME",
			Description: "create private key + cert signed by CA",
			Action:      createBundle,
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "ca",
					Usage: "certificate authority",
				},
				cli.BoolFlag{
					Name:  "client",
					Usage: "generate a client certificate (default is server)",
				},
				cli.IntFlag{
					Name:  "expire",
					Usage: "expiration limit in days",
					Value: 365,
				},
				cli.StringFlag{
					Name:  "filename",
					Usage: "filename for bundle, use when you generate multiple certs for same cn",
				},
				cli.StringFlag{
					Name:   "organization",
					EnvVar: "PKI_ORGANIZATION",
				},
				cli.StringFlag{
					Name:   "organizational-unit",
					EnvVar: "PKI_ORGANIZATIONAL_UNIT",
				},
				cli.StringFlag{
					Name:   "locality",
					EnvVar: "PKI_LOCALITY",
				},
				cli.StringFlag{
					Name:   "country",
					EnvVar: "PKI_COUNTRY",
					Usage:  "Country name, 2 letter code",
				},
				cli.StringFlag{
					Name:   "province",
					Usage:  "province/state",
					EnvVar: "PKI_PROVINCE",
				},
				cli.StringSliceFlag{
					Name:  "dns, d",
					Usage: "dns alt names",
				},
				cli.StringSliceFlag{
					Name:  "ip, i",
					Usage: "IP alt names",
				},
				cli.StringSliceFlag{
					Name:  "email, e",
					Usage: "Email alt names",
				},
			},
		},
	}

	app.Run(os.Args)
}

func main() {
	parseArgs()
}
