mkdir certs
rm certs/*
echo "generate pseudo CA private key"
openssl genrsa -out certs/ca.key 2048

echo "generate pseudo CA certificate signing request"
openssl req -new -sha256 -days 3650 \
        -key certs/ca.key -out certs/ca.csr \
        -config ./cert-conf/ca.conf

echo "generate pseudo CA certificate"
openssl x509 \
    -req \
    -days 3650 \
    -in certs/ca.csr \
    -signkey certs/ca.key \
    -out certs/ca.crt

echo "generate server private key"
openssl ecparam -genkey -name secp384r1 \
        -out certs/server.key

echo "generate server certificate signing request"
openssl req -new -key certs/server.key \
        -out certs/server.csr \
        -config ./cert-conf/server.conf

echo "CA sign server csr"
openssl x509 \
  -req \
  -days 3650 \
  -CA certs/ca.crt \
  -CAkey certs/ca.key \
  -CAcreateserial \
  -in certs/server.csr \
  -out certs/server.pem\
  -extensions req_ext \
  -extfile cert-conf/server.conf

echo "generate verifier private key"
openssl ecparam -genkey -name secp384r1 \
        -out certs/verifier-https-app.key

echo "generate verifier certificate signing request"
openssl req -new -key certs/verifier-https-app.key \
        -out certs/verifier-https-app.csr -config \
         ./cert-conf/verifier-https-app.conf

echo "CA sign verifier csr"
openssl x509 \
  -req \
  -days 3650 \
  -CA certs/ca.crt \
  -CAkey certs/ca.key \
  -CAcreateserial \
  -in certs/verifier-https-app.csr \
  -out certs/verifier-https-app.pem\
  -extensions req_ext \
  -extfile cert-conf/verifier-https-app.conf
