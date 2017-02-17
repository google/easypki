[![Build
Status](https://travis-ci.org/google/easypki.svg?branch=master)](https://travis-ci.org/google/easypki)
[![codecov](https://codecov.io/gh/google/easypki/branch/master/graph/badge.svg)](https://codecov.io/gh/google/easypki)

easypki
======

Easy Public Key Infrastructure intends to provide most of the components needed
to manage a PKI, so you can either use the API in your automation, or use the
CLI.

# API

[![godoc](https://godoc.org/github.com/google/easypki?status.svg)](https://godoc.org/github.com/google/easypki)

For the latest API:

```
import "gopkg.in/google/easypki.v1"
```

## Legacy API

API below pkg/ has been rewritten to allow extensibility in terms of PKI
storage and better readability.

If you used the legacy API that was only writing files to disk, a tag has been
applied so you can still import it:

```
import "gopkg.in/google/easypki.v0"
```

# CLI

Current implementation of the CLI uses the local store and uses a structure
compatible with openssl, so you are not restrained.

```
# Get the CLI:
go get github.com/google/easypki/cmd/easypki


# You can also pass the following through arguments if you do not want to use
# env variables.
export PKI_ROOT=/tmp/pki
export PKI_ORGANIZATION="Acme Inc."
export PKI_ORGANIZATIONAL_UNIT=IT
export PKI_COUNTRY=US
export PKI_LOCALITY="Agloe"
export PKI_PROVINCE="New York"

mkdir $PKI_ROOT

# Create the root CA:
easypki create --filename root --ca "Acme Inc. Certificate Authority"

# In the following commands, ca-name corresponds to the filename containing
# the CA.

# Create a server certificate for blog.acme.com and www.acme.com:
easypki create --ca-name root --dns blog.acme.com --dns www.acme.com www.acme.com

# Create an intermediate CA:
easypki create --ca-name root --filename intermediate --intermediate "Acme Inc. - Internal CA"

# Create a wildcard certificate for internal use, signed by the intermediate ca:
easypki create --ca-name intermediate --dns "*.internal.acme.com" "*.internal.acme.com"

# Create a client certificate:
easypki create --ca-name intermediate --client --email bob@acme.com bob@acme.com

# Revoke the www certificate.
easypki revoke $PKI_ROOT/root/certs/www.acme.com.crt

# Generate a CRL expiring in 1 day (PEM Output on stdout):
easypki crl --ca-name root --expire 1
```
You will find the generated certificates in `$PKI_ROOT/ca_name/certs/` and
private keys in `$PKI_ROOT/ca_name/keys/`

For more info about available flags, checkout out the help `easypki -h`.

# Disclaimer

This is not an official Google product.
