package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
)

func main() {
	privKeyBytes, err := ioutil.ReadFile("private.pem")
	if err != nil {
		log.Fatal(err)
	}

	pubKeyBytes, err := ioutil.ReadFile("public.pem")
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(privKeyBytes)
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	block, _ = pem.Decode(pubKeyBytes)
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	data := "This is a message"

	encMessage, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey.(*rsa.PublicKey), []byte(data))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(encMessage))

	decMessage, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, encMessage)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", string(decMessage))
}
