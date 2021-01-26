package sender

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"email_pgp/utils"
	"encoding/pem"
	"io/ioutil"
	"log"
)

func generateKeys() {
	key := utils.GenerateRSAKey(4096)
	publicKey := key.PublicKey
	utils.SavePEMKey("keys/alice_private.pem", key)
	utils.SavePublicPEMKey("keys/alice_public.pem", publicKey)
}

func getPublicKey() *rsa.PublicKey {

	file, err := ioutil.ReadFile("keys/bob_public.pem")
	utils.CheckError(err)

	block, _ := pem.Decode(file)
	if block == nil || block.Type != "PUBLIC KEY" {
		log.Fatal("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	utils.CheckError(err)

	// casting is very weired in Go
	// this casts pub to *rsa.PublicKey
	return pub
}

func pKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// SendMail return void
func SendMail(keysOnly bool) string {
	if keysOnly {
		generateKeys()
		println("Generated the sender Public/Private keys in the keys sub-directory")
		return ""
	}

	// 8 bytes are 64 bits
	desKey := make([]byte, 8)

	_, err := rand.Read(desKey)
	utils.CheckError(err)
	desKey[7] = 0 // set the last byte to 0 to force 56 bit key
	println("deskey in send: ", (desKey))

	bobPublic := getPublicKey()

	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, bobPublic, desKey)
	utils.CheckError(err)

	//err = ioutil.WriteFile("keys/ks.txt", encryptedKey, 0644)
	//utils.CheckError(err)

	block, err := des.NewCipher(desKey)
	utils.CheckError(err)

	msg, err := ioutil.ReadFile("email.txt")
	utils.CheckError(err)

	iv := []byte{0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC}

	blockSize := block.BlockSize()
	origData := pKCS5Padding(msg, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)

	// * THIS IS THE OUTPUT
	str := string(encryptedKey) + "__SEP__" + string(crypted)
	// println(str)
	utils.SendGmail([]byte(str))

	return str
}
