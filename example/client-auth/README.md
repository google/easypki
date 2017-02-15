# Client authentication

In this example, we generate a PKI based on a yaml definition, then we
provision a nginx server that will only allow connections from clients
having a trusted certificate.

Build the PKI from the yaml definition:

```
go run client-auth.go -config_path pki.yaml -db_path pki.boltdb
```

Fetch the certificates needed for nginx:

```
go run client-auth.go -db_path pki.boltdb -ca_name "Admins Intermediate CA" -bundle_name "localhost"
go run client-auth.go -db_path pki.boltdb -bundle_name "Admins Intermediate CA"
```

Create the nginx config structure:

```
mkdir conf.d
cp nginx.conf conf.d/
mv localhost+chain.crt localhost.key conf.d/
mv Admins\ Intermediate\ CA+chain.crt conf.d/trusted+chain.crt
```

To import the client certs in a browser we need a pkcs12 file, unfortunately
golang.org/x/crypto/pkcs12 only provides decoding, so we use openssl.

Fetch the client certificate and create a pkcs12 formatted file:

```
go run client-auth.go -db_path pki.boltdb -ca_name "Admins Intermediate CA" -bundle_name bob@acme.com -full_chain=false
cat bob@acme.com.{key,crt} | openssl pkcs12 -export -out bob@acme.com+pkcs12.crt
```

Import bob@acme.com+pkcs12.crt in your favorite browser.

Fetch the root CA to import in the browser:

```
go run client-auth.go -db_path pki.boltdb -bundle_name "CA"
```

Import CA+chain.crt in your favorite browser.

Run nginx:

```
docker run --rm -v $PWD/conf.d:/etc/nginx/conf.d -p 8080:443  nginx
```

Open you browser at https://localhost:8080, and you should see "Welcome to
nginx!".

Try to remove your client certificate from your browser and you get 400 bad
request.
