package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/gob"
	"encoding/pem"
	"log"
	"os"
)

// GenerateRSAKey returns void
func GenerateRSAKey(bitSize int) *rsa.PrivateKey {

	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	CheckError(err)
	return key
}

func saveGobKey(fileName string, key interface{}) {
	outFile, err := os.Create(fileName)
	CheckError(err)
	defer outFile.Close()

	encoder := gob.NewEncoder(outFile)
	err = encoder.Encode(key)
	CheckError(err)
}

// SavePEMKey returns void
func SavePEMKey(fileName string, key *rsa.PrivateKey) {
	outFile, err := os.Create(fileName)
	CheckError(err)
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	CheckError(err)
}

// SavePublicPEMKey returns void
func SavePublicPEMKey(fileName string, pubkey rsa.PublicKey) {
	asn1Bytes, err := asn1.Marshal(pubkey)
	CheckError(err)

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	CheckError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	CheckError(err)
}

// CheckError returns void
func CheckError(err error) {
	if err != nil {
		log.Fatalln("Fatal error ", err.Error())
	}
}
