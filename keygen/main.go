package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

func main() {
	reader := rand.Reader

	key, err := rsa.GenerateKey(reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	publicKey := key.Public()

	var privateKey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	fpriv, err := os.Create("private.pem")
	if err != nil {
		log.Fatal(err)
	}
	defer fpriv.Close()

	err = pem.Encode(fpriv, privateKey)
	if err != nil {
		log.Fatal(err)
	}

	pkixKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Fatal(err)
	}

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkixKey,
	}

	fpub, err := os.Create("public.pem")
	if err != nil {
		log.Fatal(err)
	}
	defer fpub.Close()

	err = pem.Encode(fpub, pemkey)
	if err != nil {
		log.Fatal(err)
	}
}
