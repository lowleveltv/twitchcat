#!/bin/sh

openssl x509 -req -in ../client/key/clientcsr.csr -CA key/server.crt -CAkey ./key/server.key -CAcreateserial -out ../client/key/client.crt -days 3650 -sha256 -extfile <(printf "subjectAltName=DNS:fritz.box,IP:127.0.0.1")
