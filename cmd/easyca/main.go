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
	"github.com/jeremy-clerc/easyca/pkg/easyca"
)

// https://access.redhat.com/documentation/en-US/Red_Hat_Certificate_System/8.0/html/Admin_Guide/Standard_X.509_v3_Certificate_Extensions.html
// B.3.8. keyUsage

func initPki(c *cli.Context) {
	log.Print("generating new pki structure")
	err := os.MkdirAll(filepath.Join(c.GlobalString("root"), "private"), 0755)
	if err != nil {
		log.Fatalf("creating pki structure %v", err)
	}
}

func createBundle(c *cli.Context) {
	if !c.Args().Present() {
		cli.ShowSubcommandHelp(c)
		log.Fatalf("Usage: %v name (common name defaults to name, use --cn and "+
			"different name if you need multiple certs for same cn)", c.Command.FullName())
	}

	var filename string
	commonName := strings.Join(c.Args()[:], " ")

	if len(c.String("filename")) > 0 {
		filename = c.String("filename")
	} else {
		filename = strings.Replace(commonName, " ", "_", -1)
		filename = strings.Replace(filename, "*", "wildcard", -1)
	}

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: c.StringSlice("organization"),
			Locality:     c.StringSlice("locality"),
			Country:      c.StringSlice("country"),
			Province:     c.StringSlice("province"),
		},
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
	err := easyca.GenerateCertifcate(c.GlobalString("root"), filename, template)
	if err != nil {
		log.Fatal(err)
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
			Name:   "init",
			Usage:  "create directory structure",
			Action: initPki,
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
				cli.StringSliceFlag{
					Name:   "organization",
					EnvVar: "PKI_ORGANIZATION",
				},
				cli.StringSliceFlag{
					Name:   "locality",
					EnvVar: "PKI_LOCALITY",
				},
				cli.StringSliceFlag{
					Name:   "country",
					EnvVar: "PKI_COUNTRY",
					Usage:  "Country name, 2 letter code",
				},
				cli.StringSliceFlag{
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
