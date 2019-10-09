package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
)

type publicer interface {
	Public() crypto.PublicKey
}

func main() {
	privKeyBytes, err := ioutil.ReadFile("private.pem")
	if err != nil {
		log.Fatal(err)
	}

	block, rest := pem.Decode(privKeyBytes)
	if block == nil {
		log.Fatalf("No block found: %s\n", string(rest))
	}
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	pubber, ok := privKey.(publicer)
	if !ok {
		log.Fatalf("Can't create public key from private key provided.\n")
	}
	publicKey := pubber.Public()

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
	_ = pem.Encode(os.Stdout, pemkey)

}
