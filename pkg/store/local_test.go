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

package store

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/easypki/pkg/certificate"
)

var (
	pemKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAxGJ/tXy7ItxDpI9RLb0L/mkxGpw+BodijFoNixq0QEzxsc+t
Lr+3czb00a0B/kzObV0AQYwXFqdJ+qb7jZXc3To6iALDw3ghWNgfaBeIKPueY6n7
7DU4ZpzjLy8DhlWO44Vx6CZjByr6qmGh3TnDqD8sVEFPZlattgHy4KfTmc0abk4b
wlJ4lvpXBshl1SYsMgpyZrTC1mggcu+xw98EcvLollYKvW4WyYtTbwBo5S8c/hVt
m2nbxLZgUui5wMPmEmtvxnfYeB4kL8LHNMtxT1Pw6JLd4vUL00k8GrUfEa+2J3FG
euG9dCI1ZS1N5Z/UN0Odq4QCs8ILexAgj99XLwIDAQABAoIBAQCXqUnfKriKr3g9
ucCDhh+hFjOpzUfJWvysT09uQe06SzHMlAm2tLBD9gkTdHy5my9AHjZ4aGvcPs1P
GW3jZfzvjGxvZVMxvbBjIGUAykuI+ujTJw861876z+ZTJgee0qxK4V+aXSrU+kgj
FMsgQd/sKv1dBCMBcactjEu5W2J6vyQ3N7kq9gA/+VQ6yPaPN6y+DTgyZTkG4oXU
5vetosdvm8MzuvGZlYf/LEtiYfFSpLmg1EzHO1Z6mJ2NOkT4GJ1JIltIWk0Mm3xl
4Co4zwlKebEGEN0jJ7Rs67ZIcWgcTfOd1xnwabEC04EnN6UhuE8fXZWOuqLFxVg1
UKl8U7zBAoGBAOlBqcLr4P5GeqrH65P2HfkaKLI9V+fip3gO7taWRn7XxX5BMzfr
vBJabRif+nd8eqKrLw+6l1cSBc/6kdunyINoYDfhgEFXfb1tKKc74x4k8xVdsVEU
X+e2nM2+uGe5afnMX61qYNHLa8LDUI0q/Aj5813F0Akj9FxdNMU3T/jpAoGBANeI
ehmT5zvtmFCXqAbb3U6kGjUv/eM016NbDn1l6QVhs4qqm1x1CRwP16qjvU9yLwDr
/QTRWBBAQpR7vzHY+qE768FCJj0zPNU40R2uXXrVYyqm+WhzBuO1kZtlUNwZLW/m
Ek6h0HJdCoNpTxBbUWIdI/TQPEr5hFTtdOf/C8BXAoGBALubU5XyMBFz0F+h0mk8
L9lV39uUGSrpkraulAzF60dD9pVYjYBxut+sGUkQCtylouFI+94TvnuKhGBF8aCQ
72Y5wgHP/l8PppN/w43WThLFtzm9FMvYrlZo+u9EcX8DkygV5/JLuDmk+jQ48YXJ
R9NUbhhC7NMdNwI++R2SImFZAoGBAI4tmV4GEyOVOETxxgXAQ9z8o80yO2kGErnP
918BOxYxvR5cLOBw0/GPAdWu7dLan+cbxWzILC+MNF9+wkE/wRVbUcnKuS7l/dsp
/8h0nXXKDgC05RHhz0mnHMZFr3GBqleGjc0RMVA/0A+gCGfh1W3Di1STiTJsJr9f
ZR8lP7tBAoGAVbnEDpvT9pNxKhXd3PzQqjsM+DUeqnpvxT4O5wKJ+M2Bn17VOHMj
JXZMs55G8qITwK3q2BRs+hCvrfAM5oQClv3MwQ4ItqYH24Ed7rU3yA90/LXioXgZ
5zWBV7LaFFBReJlmsAmEf85eKPRG/OrfoxxHwpGTSnJgU/zuciNgLD8=
-----END RSA PRIVATE KEY-----`)

	pemRootCACert = []byte(`-----BEGIN CERTIFICATE-----
MIIDuzCCAqOgAwIBAgIQBDsLj8sbZAngX2d7OwD1ZzANBgkqhkiG9w0BAQsFADBn
MQswCQYDVQQGEwJVUzERMA8GA1UECBMITmV3IFlvcmsxDjAMBgNVBAcTBUFnbG9l
MRYwFAYDVQQKEw1VbWJyZWxsYSBDb3JwMQswCQYDVQQLEwJJVDEQMA4GA1UEAxMH
Um9vdCBDQTAeFw0xNzAyMTQxMjE5NTZaFw0xODAyMTQxMjE5NTZaMGcxCzAJBgNV
BAYTAlVTMREwDwYDVQQIEwhOZXcgWW9yazEOMAwGA1UEBxMFQWdsb2UxFjAUBgNV
BAoTDVVtYnJlbGxhIENvcnAxCzAJBgNVBAsTAklUMRAwDgYDVQQDEwdSb290IENB
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxGJ/tXy7ItxDpI9RLb0L
/mkxGpw+BodijFoNixq0QEzxsc+tLr+3czb00a0B/kzObV0AQYwXFqdJ+qb7jZXc
3To6iALDw3ghWNgfaBeIKPueY6n77DU4ZpzjLy8DhlWO44Vx6CZjByr6qmGh3TnD
qD8sVEFPZlattgHy4KfTmc0abk4bwlJ4lvpXBshl1SYsMgpyZrTC1mggcu+xw98E
cvLollYKvW4WyYtTbwBo5S8c/hVtm2nbxLZgUui5wMPmEmtvxnfYeB4kL8LHNMtx
T1Pw6JLd4vUL00k8GrUfEa+2J3FGeuG9dCI1ZS1N5Z/UN0Odq4QCs8ILexAgj99X
LwIDAQABo2MwYTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
HQ4EFgQUqHqzyLJ/FARR2FjEK+KgEa1mm28wHwYDVR0jBBgwFoAUqHqzyLJ/FARR
2FjEK+KgEa1mm28wDQYJKoZIhvcNAQELBQADggEBAI8gE4wo13oMpBM5YgIIcUhI
0S1N4Z1F+n48aJU9JcQvHSpdOt1RkVhh6jUVkU9+HRv1Eu+4SMfIVswLF9y+jNzf
vPIYGcrXh5jIWybte8PwPQ3AzRBoyxDXCkQyFSb/CLVT7oC+fQje1DeIJeNPNdav
Cm+VrNZPVlFhD2Mbp+Jcn370xBoP5hLeq3JtO954UnBBM7ntN74n2J63JAuroqME
SwXQznqZmQHv3oJZ6DU5JThzsSWKF7aarp6xMzD+UVX2T1vAq/qI6xGfPI8qAQyu
PFM1z1LC4UMUTDN0IxOqRluF4z4GnqqODqrI6SAbt+raLZp3pcHhbtLQYs641iw=
-----END CERTIFICATE-----`)

	pemIntCACert = []byte(`-----BEGIN CERTIFICATE-----
MIIDwzCCAqugAwIBAgIQZ+mGV//fgEFlN18lF/a27zANBgkqhkiG9w0BAQsFADBn
MQswCQYDVQQGEwJVUzERMA8GA1UECBMITmV3IFlvcmsxDjAMBgNVBAcTBUFnbG9l
MRYwFAYDVQQKEw1VbWJyZWxsYSBDb3JwMQswCQYDVQQLEwJJVDEQMA4GA1UEAxMH
Um9vdCBDQTAeFw0xNzAyMTQxNjE3MDFaFw0xODAyMTQxNjE3MDFaMG8xCzAJBgNV
BAYTAlVTMREwDwYDVQQIEwhOZXcgWW9yazEOMAwGA1UEBxMFQWdsb2UxFjAUBgNV
BAoTDVVtYnJlbGxhIENvcnAxCzAJBgNVBAsTAklUMRgwFgYDVQQDEw9JbnRlcm1l
ZGlhdGUgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDY+0MUX4HD
yChfufqI764pfTUTPr8uf36NZ6bfqW1Cq0uAwWRUZ4CB8Ki3JV8He4/2JmOz+xp7
DNG+yEaJYmIautYcvQBeqv8opDZkYzATrV8kOMj1DcL5ihVCu0jI+PmyN3KgEhEl
dAT82A2ZZbwriiIMNznnVuqC95tuorzDz8gUC9bDNeYusz9eeM8/xxNvcbT7jJiM
ydbZmSeVxdibRyLvsZbttx+I2q9LAkoSzoz4iJwoegYRaq+S8J8wrnc4hkxsZNAB
TXZXS0ep3kjnc9EPa3AYr8k5Pwbe5mvhA8jRKerDrmLkr/LESvF8kw2qNBi86dt2
U4VxQ9Fh9z1rAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTAD
AQH/MB0GA1UdDgQWBBTsosyPYEK2xxbejYe1Zop9rgc3oTAfBgNVHSMEGDAWgBSo
erPIsn8UBFHYWMQr4qARrWabbzANBgkqhkiG9w0BAQsFAAOCAQEAqIQyEPvAaod5
kfcHgL8QiLQfJBGzNDMVXOGZBGc2CzZiU2s5y3q4uzDiFSqrq07WKuWnwayEqX2W
D2ULB0E7kgNqus40kfot3OgXmk84g3i1YkVP+NxkO+a8ldsXwKbNCG371XGeFfyB
qxuSikQd/BO3aszHqZ2AhFS6PJQ1T80UqkQQ8DGfYyIQ9xwt0v36JDwOkXCIGhsb
/3uROzf+oeENufAxNxzIOInp8R2D1K/zF920Mu9MjzvP+iLe9G9o6YsshwGnjNIi
wv1CeyVUseZ1gjEDm8zuCjC1CAjyQPL1xO679ao8Vd/5qLlp6Y9JYrTtoI2pv/A2
07JWb8O0hA==
-----END CERTIFICATE-----`)

	pemSrvCert = []byte(`-----BEGIN CERTIFICATE-----
MIID8TCCAtmgAwIBAgIQJCo3GykFfMMGhMlNIH1+iDANBgkqhkiG9w0BAQsFADBv
MQswCQYDVQQGEwJVUzERMA8GA1UECBMITmV3IFlvcmsxDjAMBgNVBAcTBUFnbG9l
MRYwFAYDVQQKEw1VbWJyZWxsYSBDb3JwMQswCQYDVQQLEwJJVDEYMBYGA1UEAxMP
SW50ZXJtZWRpYXRlIENBMB4XDTE3MDIxNDE2Mjg0NloXDTE4MDIxNDE2Mjg0Nlow
bDELMAkGA1UEBhMCVVMxETAPBgNVBAgTCE5ldyBZb3JrMQ4wDAYDVQQHEwVBZ2xv
ZTEWMBQGA1UEChMNVW1icmVsbGEgQ29ycDELMAkGA1UECxMCSVQxFTATBgNVBAMT
DHd3dy5hY21lLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJW
b34KP7aJO7fbAWK9W8sGZoa+/gvWYccsVrwip8Lfsn45OBCnvx4pu39oY8/6v4K9
5u1i3aR6hZSOWIpf06uEuGJypU2Smv8GtqRjWIUcSvhfGJJQl2GL6jbatLL8HchZ
jJxAiPZJZkpnV02Yb8E2KrgAxbFMRctyuXVzEmTUE2xRqFgGNz39tchsuQ902YgN
Wb11TUqEt8BzY6+lLj8iLDyeCGNK4SmybiYTbut2eqngGSqBnAAKcfaOtvoBj7uU
U/pJCreeAFrN/R3oQwotsJo2FhlExeeYiYxU1t50Y3bITXUx7Ze1lytQ7EayyZcB
sBNSYSt/AoINJh/ALi0CAwEAAaOBizCBiDAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0l
BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBQvLOeEGINkRV14Abu7
vx5ofyor/zAfBgNVHSMEGDAWgBTsosyPYEK2xxbejYe1Zop9rgc3oTAXBgNVHREE
EDAOggx3d3cuYWNtZS5jb20wDQYJKoZIhvcNAQELBQADggEBADah9ESMERTgJX9W
SMc/yQ5NPaT2Mr7F4pySMWzCh0pJqJPded9L9lWGWbVGY/pBBqixZbl2b1TzTuK9
Zv0636+QuerVpeSwV1DHvc5d8+ov3b9Ehp2qIpQZGA0OEmHdftocJr/IjzJhtAzF
dJJvIfjc2QZPb356+SfHO/tgXkhsTHReiAEYuVbr+Xl4xuIyubQW6ZWpoxM+Ejb+
JH7yaDXSwHuwAKvcY6a7E1li+yIBrQAIWTl9CiCEu29j+tvN6MdqbL9/FWviPpwt
QyzYCwoRBHrQOo4pzXV2ZYKGeh7GZr7cpeG2VJ1Ds7axCJsIqoxLgKwh3LJslt8f
0AKvvlM=
-----END CERTIFICATE-----`)

	pemCliCert = []byte(`-----BEGIN CERTIFICATE-----
MIID5jCCAs6gAwIBAgIQei07JTnGMAsKHPdEFVY1rjANBgkqhkiG9w0BAQsFADBv
MQswCQYDVQQGEwJVUzERMA8GA1UECBMITmV3IFlvcmsxDjAMBgNVBAcTBUFnbG9l
MRYwFAYDVQQKEw1VbWJyZWxsYSBDb3JwMQswCQYDVQQLEwJJVDEYMBYGA1UEAxMP
SW50ZXJtZWRpYXRlIENBMB4XDTE3MDIxNDE2MjkwMloXDTE4MDIxNDE2MjkwMlow
bDELMAkGA1UEBhMCVVMxETAPBgNVBAgTCE5ldyBZb3JrMQ4wDAYDVQQHEwVBZ2xv
ZTEWMBQGA1UEChMNVW1icmVsbGEgQ29ycDELMAkGA1UECxMCSVQxFTATBgNVBAMM
DGJvYkBhY21lLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANNX
gZ31L66+rDpDVX4XRmwHVRVKCDX+O/Q4vE60lJGBkp103HlmnqKTWlLpVARO/LHH
ifnK2cl+zzE6zs5rT94zEQCY38lIDKaCbbGNrVYHjm2q3cV71VAh69C0ErfWwUEa
duIZtKOJ+e1L3SUJ0hX2chZNrN7Ns3JiyQu+Ec0MjQn/39F58IZolBHUP9MuGujm
OaIaGu8K1pU9HLRjII9rODMTQQhH8KT8mpvKddcuvXNZevN2kqNbosQxeIK9ZV6P
G86nQtOcyGF5giQfVX+HlRk8ZhFC1A0STs/R3GVAZCo8zeCoKmzmbxiJBIVOizT1
kySR7YAPnCV2odI5rDcCAwEAAaOBgDB+MA4GA1UdDwEB/wQEAwIFoDATBgNVHSUE
DDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUS6Z8HszoqiAJ9tP8DP+u+DCyAW0wHwYD
VR0jBBgwFoAU7KLMj2BCtscW3o2HtWaKfa4HN6EwFwYDVR0RBBAwDoEMYm9iQGFj
bWUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQAly+KRHuRSNCoDDqbp3F8p7vXx4I6O
fDtbg/VPwSdbjL/t/wCkDBzuK5Iba5IiKI8lEg7H9VXt740cXhlcPbNUhPRJvPjz
nqoFGPZcWFF4UqGY2RyLAb9FlT1i9nf1BUUfeVGllhB8RTbALQKOKyzQGZ7aSDdo
cm0f8WMh6qWKgMCDchWjyvYdTI1Td7CirLyAmSaaNcjKtEX11l97bseh9V+vFHEK
2kyagXIXEGUXNeBKRfIY4rbEvZ6GAWjoegTZF+b12MOEICIgzQ+hJASvcU/wLAzD
HhXyi8+5HkbcAinttHF71DCfdGQraHcY/hjraWq9uNq9zHOYUOnvtbGr
-----END CERTIFICATE-----`)

	expectedIndex = []byte(`V	180214162846Z		242A371B29057CC30684C94D207D7E88	www.acme.com.crt	/C=US/O=Umbrella Corp/OU=IT/L=Agloe/ST=New York/CN=www.acme.com
V	180214162902Z		7A2D3B2539C6300B0A1CF744155635AE	bob@acme.com.crt	/C=US/O=Umbrella Corp/OU=IT/L=Agloe/ST=New York/CN=bob@acme.com
`)
)

// pemToDer returns the private key and root CA certificate, intermediate CA
// certificate, server certificate and client certificate DER encoded.
func pemToDER() ([]byte, []byte, []byte, []byte, []byte, error) {
	k, _ := pem.Decode(pemKey)
	if k == nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("no PEM data found for certificate")
	}
	rootCA, _ := pem.Decode(pemRootCACert)
	if rootCA == nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("no PEM data found for certificate")
	}
	intCA, _ := pem.Decode(pemIntCACert)
	if intCA == nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("no PEM data found for certificate")
	}
	srv, _ := pem.Decode(pemSrvCert)
	if srv == nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("no PEM data found for certificate")
	}
	cli, _ := pem.Decode(pemCliCert)
	if cli == nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("no PEM data found for certificate")
	}
	return k.Bytes, rootCA.Bytes, intCA.Bytes, srv.Bytes, cli.Bytes, nil
}

func TestLocal(t *testing.T) {
	dir, err := ioutil.TempDir("", "localstore")
	if err != nil {
		t.Fatalf("failed creating temporary directory: %v", err)
	}
	defer os.RemoveAll(dir)

	local := &Local{Root: dir}

	derKey, derRootCA, derIntCA, derSrv, derCli, err := pemToDER()
	if err != nil {
		t.Fatalf("pemToDER(): got error %v != expected nil", err)
	}

	bundleToAdd := []struct {
		signer string
		name   string
		isCA   bool
		crt    []byte
	}{
		{"Root_CA", "Root_CA", true, derRootCA},
		{"Root_CA", "Intermediate_CA", true, derIntCA},
		{"Intermediate_CA", "www.acme.com", false, derSrv},
		{"Intermediate_CA", "bob@acme.com", false, derCli},
	}
	for _, bundle := range bundleToAdd {
		if err := local.Add(bundle.signer, bundle.name, bundle.isCA, derKey, bundle.crt); err != nil {
			t.Fatalf("Add(%v, %v, %v, ...): got error %v != nil", bundle.signer, bundle.name, bundle.isCA, err)
		}
	}
	expectedFiles := []struct {
		ca   string
		name string
	}{
		{"Root_CA", "Root_CA"},
		{"Root_CA", "Intermediate_CA"},
		{"Intermediate_CA", "Intermediate_CA"},
		{"Intermediate_CA", "www.acme.com"},
		{"Intermediate_CA", "bob@acme.com"},
	}
	for _, file := range expectedFiles {
		k, c := local.path(file.ca, file.name)
		if _, err := os.Stat(k); err != nil {
			t.Errorf("Key %v is not present: %v", k, err)
		}
		if _, err := os.Stat(c); err != nil {
			t.Errorf("Certificate %v is not present: %v", c, err)
		}
	}
	indexPath := filepath.Join(local.Root, "Intermediate_CA", "index.txt")
	index, err := ioutil.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("ReadFile(%v): got error %v != expected nil", indexPath, err)
	}
	if !reflect.DeepEqual(index, expectedIndex) {
		t.Errorf("Intermediate_CA index:\n%v\n!= expected:\n%v", string(index), string(expectedIndex))
	}

	rawSrvKey, rawSrvCrt, err := local.Fetch("Intermediate_CA", "www.acme.com")
	if err != nil {
		t.Fatalf("Fetch(Intermediate_CA, www.acme.com): got error %v != expected nil", err)
	}
	if !reflect.DeepEqual(rawSrvKey, derKey) {
		t.Error("www.acme.com key from disk does not match expected key.")
	}
	if !reflect.DeepEqual(rawSrvCrt, derSrv) {
		t.Error("www.acme.com cert from disk does not match expected key.")
	}

	srvCrt, err := x509.ParseCertificate(derSrv)
	if err != nil {
		t.Fatalf("ParseCertificate(derSrv): got error %v != expected nil", err)
	}

	if err := local.Update("Intermediate_CA", srvCrt.SerialNumber, certificate.Revoked); err != nil {
		t.Fatalf("Update(Intermediate_CA, Server cert serial, certificate.Revoked): got error %v != expected nil", err)
	}

	revoked, err := local.Revoked("Intermediate_CA")
	if err != nil {
		t.Fatalf("Revoked(Intermediate_CA): got error %v != expected nil", err)
	}
	if len(revoked) != 1 {
		t.Fatalf("Got %v revoked certs != expected 1", len(revoked))
	}
	if revoked[0].SerialNumber.Cmp(srvCrt.SerialNumber) != 0 {
		t.Errorf("Revoked cert serial number %v != expected serial number %v", revoked[0].SerialNumber, srvCrt.SerialNumber)
	}
}
