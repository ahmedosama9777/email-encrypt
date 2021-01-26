package receiver

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"email_pgp/utils"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
)

func generateKeys() {
	key := utils.GenerateRSAKey(4096)

	publicKey := key.PublicKey
	utils.SavePEMKey("keys/bob_private.pem", key)
	utils.SavePublicPEMKey("keys/bob_public.pem", publicKey)
}

func getPrivateKey() *rsa.PrivateKey {

	file, err := ioutil.ReadFile("keys/bob_private.pem")
	utils.CheckError(err)

	block, _ := pem.Decode(file)
	if block == nil || block.Type != "PRIVATE KEY" {
		log.Fatal("failed to decode PEM block containing private key")
	}

	pub, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	utils.CheckError(err)

	// casting is very weired in Go
	// this casts pub to *rsa.PublicKey
	return pub
}

func pKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

// ReceiveMail return void
func ReceiveMail(keysOnly bool, enc string) {
	if keysOnly {
		generateKeys()
		println("Generated the receiver Public/Private keys in the keys sub-directory")
		return
	}

	//encDesKey, err := ioutil.ReadFile("keys/ks.txt")
	//utils.CheckError(err)

	msgs := utils.ReceiveGmail("ahmedosama9777@gmail.com")

	for idx, msg := range msgs {
		decreptedMessage := make([]byte, len(msg))
		// println(string(msg))

		realMsg, err := base64.URLEncoding.DecodeString(string(msg))
		utils.CheckError(err)

		msgAndKey := strings.Split(string(realMsg), "__SEP__")

		desKey := make([]byte, 8)

		err = rsa.DecryptPKCS1v15SessionKey(rand.Reader, getPrivateKey(), []byte(msgAndKey[0]), desKey)
		utils.CheckError(err)

		// println("deskey in receive: ", string(desKey))

		block, err := des.NewCipher(desKey)
		utils.CheckError(err)

		iv := []byte{0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC}

		decr := cipher.NewCBCDecrypter(block, iv)

		decr.CryptBlocks(decreptedMessage, []byte(msgAndKey[1]))
		pKCS5UnPadding(decreptedMessage)

		trimmedStr := strings.Replace(string(decreptedMessage), "\x00", "", -1) //strings.TrimFunc(string(decreptedMessage), func(r rune) bool { return r == 0 })

		ioutil.WriteFile(fmt.Sprintf("received_emails/decoded_email_%d.txt", idx), pKCS5UnPadding([]byte(trimmedStr)), 0644)
		fmt.Println(fmt.Sprintf("Message %d received", idx))
		fmt.Println(string(decreptedMessage))
		fmt.Println("__________________________________________________________________")
	}

	if len(msgs) == 0 {
		fmt.Println("There is no encrypted emails at the moment, go make one.")
	}

}
