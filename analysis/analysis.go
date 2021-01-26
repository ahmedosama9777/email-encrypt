package analysis

import (
	"bytes"
	"crypto/rand"
	"crypto/des"
	"crypto/cipher"
	"email_pgp/utils"
	"io/ioutil"
	"log"
	"time"
)
func pKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}
// SendMail return string
func GenCipher(desKey []byte) string {
	
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
	//println("crypted:", string(crypted))
	return string(crypted)
}

//Brute force attack on DES
func desBrute(desBits int) bool {
	if desBits == 8 {
		start := time.Now()
		call := BruteEight()
		elapsed := time.Since(start)
		if call {
			log.Printf("Breaking 8-bit key took: %s", elapsed)
			return call
		}
	}
	if desBits == 16 {
		start := time.Now()
		call := BruteSixteen()
		elapsed := time.Since(start)
		if call {
			log.Printf("Breaking 16-bit key took: %s", elapsed)
			return call
		}
	}
	if desBits == 24 {
		start := time.Now()
		call := BruteTwentyFour()
		elapsed := time.Since(start)
		if call {
			log.Printf("Breaking 24-bit key took: %s", elapsed)
			return call
		}
	}
	if desBits == 32 {
		start := time.Now()
		call := BruteThirtyTwo()
		elapsed := time.Since(start)
		if call {
			log.Printf("Breaking 32-bit key took: %s", elapsed)
			return call
		}
	}
	if desBits == 40 {
		start := time.Now()
		call := BruteFourty()
		elapsed := time.Since(start)
		if call {
			log.Printf("Breaking 40-bit key took: %s", elapsed)
			return call
		}
	}
	if desBits == 48 {
		start := time.Now()
		call := BruteFourtyEight()
		elapsed := time.Since(start)
		if call {
			log.Printf("Breaking 48-bit key took: %s", elapsed)
			return call
		}
	}
	if desBits == 56 {
		start := time.Now()
		call := BruteFiftySix()
		elapsed := time.Since(start)
		if call {
			log.Printf("Breaking 56-bit key took: %s", elapsed)
			return call
		}
	}
	return false
}
func BruteEight() bool {
	desKey := make([]byte, 8)
	_, err := rand.Read(desKey)
	utils.CheckError(err)
	for i := 7; i > 0; i-- {
		desKey[i] = 0
	}
	ciphered := GenCipher(desKey)
	desKey[0] = 0 
	for i := 0; i < 255; i++ {
		attackedCipher := GenCipher(desKey)
		result := ciphered == attackedCipher
		if result {
			println("Key hacked!")
			return result
		}
		desKey[0] = desKey[0] + 1
	}
	println("Attack failed!")
	return false
}
func BruteSixteen() bool {
	desKey := make([]byte, 8)
	_, err := rand.Read(desKey)
	utils.CheckError(err)
	for i := 7; i > 1; i-- {
		desKey[i] = 0
	}
	ciphered := GenCipher(desKey)
	desKey[0] = 0 
	desKey[1] = 0
	for i := 0; i < 255; i++ {
		for j := 0; j < 255; j++ {
			attackedCipher := GenCipher(desKey)
			result := ciphered == attackedCipher
			if result {
				println("Key hacked!")
				return result
			}
			desKey[0] = desKey[0] +1
		}
		desKey[1] = desKey[1] + 1
	}
	println("Attack failed!")
	return false
}
func BruteTwentyFour() bool {
	desKey := make([]byte, 8)
	_, err := rand.Read(desKey)
	utils.CheckError(err)
	for i := 7; i > 2; i-- {
		desKey[i] = 0
	}
	ciphered := GenCipher(desKey)
	desKey[0] = 0 
	desKey[1] = 0
	desKey[2] = 0
	for k :=0; k < 255; k++ {
		for i := 0; i < 255; i++ {
			for j := 0; j < 255; j++ {
				attackedCipher := GenCipher(desKey)
				result := ciphered == attackedCipher
				if result {
					println("Key hacked!")
					return result
				}
				desKey[0] = desKey[0] +1
			}
			desKey[1] = desKey[1] + 1
		}
		desKey[2] = desKey[2] + 1
	}	
	println("Attack failed!")
	return false
}
func BruteThirtyTwo() bool {
	desKey := make([]byte, 8)
	_, err := rand.Read(desKey)
	utils.CheckError(err)
	for i := 7; i > 3; i-- {
		desKey[i] = 0
	}
	ciphered := GenCipher(desKey)
	desKey[0] = 0 
	desKey[1] = 0
	desKey[2] = 0
	desKey[3] = 0
	for l :=0; l < 255; l++ {
		for k :=0; k < 255; k++ {
			for i := 0; i < 255; i++ {
				for j := 0; j < 255; j++ {
					attackedCipher := GenCipher(desKey)
					result := ciphered == attackedCipher
					if result {
						println("Key hacked!")
						return result
					}
					desKey[0] = desKey[0] +1
				}
				desKey[1] = desKey[1] + 1
			}
			desKey[2] = desKey[2] + 1
		}
		desKey[3] = desKey[3] + 1
	}	
	println("Attack failed!")
	return false
}
func BruteFourty() bool {
	desKey := make([]byte, 8)
	_, err := rand.Read(desKey)
	utils.CheckError(err)
	for i := 7; i > 4; i-- {
		desKey[i] = 0
	}
	ciphered := GenCipher(desKey)
	desKey[0] = 0 
	desKey[1] = 0
	desKey[2] = 0
	desKey[3] = 0
	desKey[4] = 0
	for g:=0; g < 255; g++ {
		for l :=0; l < 255; l++ {
			for k :=0; k < 255; k++ {
				for i := 0; i < 255; i++ {
					for j := 0; j < 255; j++ {
						attackedCipher := GenCipher(desKey)
						result := ciphered == attackedCipher
						if result {
							println("Key hacked!")
							return result
						}
						desKey[0] = desKey[0] +1
					}
					desKey[1] = desKey[1] + 1
				}
				desKey[2] = desKey[2] + 1
			}
			desKey[3] = desKey[3] + 1
		}
		desKey[4] = desKey[4] + 1
	}	
	println("Attack failed!")
	return false
}
func BruteFourtyEight() bool {
	desKey := make([]byte, 8)
	_, err := rand.Read(desKey)
	utils.CheckError(err)
	for i := 7; i > 5; i-- {
		desKey[i] = 0
	}
	ciphered := GenCipher(desKey)
	desKey[0] = 0 
	desKey[1] = 0
	desKey[2] = 0
	desKey[3] = 0
	desKey[4] = 0
	desKey[5] = 0
	for u:=0; u<255; u++{
		for g:=0; g < 255; g++ {
			for l :=0; l < 255; l++ {
				for k :=0; k < 255; k++ {
					for i := 0; i < 255; i++ {
						for j := 0; j < 255; j++ {
							attackedCipher := GenCipher(desKey)
							result := ciphered == attackedCipher
							if result {
								println("Key hacked!")
								return result
							}
							desKey[0] = desKey[0] +1
						}
						desKey[1] = desKey[1] + 1
					}
					desKey[2] = desKey[2] + 1
				}
				desKey[3] = desKey[3] + 1
			}
			desKey[4] = desKey[4] + 1
		}
		desKey[5] = desKey[5] + 1
	}	
	println("Attack failed!")
	return false
}
func BruteFiftySix() bool {
	desKey := make([]byte, 8)
	_, err := rand.Read(desKey)
	utils.CheckError(err)
	for i := 7; i > 6; i-- {
		desKey[i] = 0
	}
	ciphered := GenCipher(desKey)
	desKey[0] = 0 
	desKey[1] = 0
	desKey[2] = 0
	desKey[3] = 0
	desKey[4] = 0
	desKey[5] = 0
	desKey[6] = 0
	for y:=0; y<255; y++ {
		for u:=0; u<255; u++{
			for g:=0; g < 255; g++ {
				for l :=0; l < 255; l++ {
					for k :=0; k < 255; k++ {
						for i := 0; i < 255; i++ {
							for j := 0; j < 255; j++ {
								attackedCipher := GenCipher(desKey)
								result := ciphered == attackedCipher
								if result {
									println("Key hacked!")
									return result
								}
								desKey[0] = desKey[0] +1
							}
							desKey[1] = desKey[1] + 1
						}
						desKey[2] = desKey[2] + 1
					}
					desKey[3] = desKey[3] + 1
				}
				desKey[4] = desKey[4] + 1
			}
			desKey[5] = desKey[5] + 1
		}
		desKey[6] = desKey[6] + 1
	}	
	println("Attack failed!")
	return false
}
// DoAnalysis ...
func DoAnalysis() {
	desBrute(8)
	desBrute(16)
	desBrute(24)
	desBrute(32)
	desBrute(40)
	desBrute(48)
	desBrute(56)
}
