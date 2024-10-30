#!/bin/bash

# Generate top level CA
openssl genrsa -out rootCA.key 2048
openssl req -x509 -new -nodes -key rootCA.key \
-days 1024 -out rootCA.crt -outform PEM

# Generate intermediate server cert
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr

# Generate signed server cert
openssl x509 -req -in server.csr -CA rootCA.crt -CAkey rootCA.key -out server.crt -days 365 -CAcreateserial

# Verify the server cert
openssl verify -CAfile rootCA.crt server.crt


echo "!!! move rootCA.crt, rootCA.key files to the 'key' folder in your key-signing-server. these will be used to issue user certificates"

echo "!!! server.key and server.crt will be used for server applications. it is not necesary for the client to verify these"
