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

package certificate

import (
	"encoding/pem"
	"fmt"
	"reflect"
	"testing"
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

	pemCert = []byte(`-----BEGIN CERTIFICATE-----
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
)

// pemToDer returns the private key and certificate key DER encoded.
func pemToDER() ([]byte, []byte, error) {
	k, _ := pem.Decode(pemKey)
	if k == nil {
		return nil, nil, fmt.Errorf("no PEM data found for certificate")
	}
	c, _ := pem.Decode(pemCert)
	if c == nil {
		return nil, nil, fmt.Errorf("no PEM data found for certificate")
	}
	return k.Bytes, c.Bytes, nil
}

func TestRawToBundle(t *testing.T) {
	k, c, err := pemToDER()
	if err != nil {
		t.Fatalf("failed retrieving fake key and cert: %v", err)
	}
	bundleName := "fakeca"
	b, err := RawToBundle(bundleName, k, c)
	if err != nil {
		t.Fatalf("RawToBundle(%v, ...): got error %v != expected nil", bundleName, err)
	}
	if b.Name != bundleName {
		t.Errorf("RawToBundle(%v, ...): got bundle name %v != expected %v", bundleName, b.Name, bundleName)
	}
	sn := "5623491996784668439572849354101290343"
	if b.Cert.SerialNumber.String() != sn {
		t.Errorf("RawToBundle(%v, ...): got cert with serial number %v != expected %v", bundleName, b.Cert.SerialNumber, sn)
	}

	rk, rc := b.Raw()
	if !reflect.DeepEqual(k, rk) {
		t.Errorf("Raw(): raw private key != raw private key used to generate bundle")
	}
	if !reflect.DeepEqual(c, rc) {
		t.Errorf("Raw(): raw certificate != raw certificate used to generate bundle")
	}

	_, err = RawToBundle("badkey", k[1:], c)
	if err == nil {
		t.Error("RawToBundle(badkey, ...): got error nil != expected failed parsing private key...")
	}
	_, err = RawToBundle("badcert", k, c[1:])
	if err == nil {
		t.Error("RawToBundle(badcert, ...): got error nil != expected failed parsing certificate...")
	}
}
