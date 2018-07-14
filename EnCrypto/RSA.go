package EnCrypto

import (
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"crypto/rand"
)

type RSA struct {
	Cry
}

func (r *RSA)EnCrypt(publicKey []byte) []byte   {
	//公钥加密
	block, _:= pem.Decode(publicKey)

	//解析公钥
	pubInterface, _ := x509.ParsePKIXPublicKey(block.Bytes)

	//加载公钥
	pub := pubInterface.(*rsa.PublicKey)

	//加密明文
	bits,_ := rsa.EncryptPKCS1v15(rand.Reader, pub, r.Data)

	//bits为最终的密文
	return bits
}


func (r *RSA)Decrypt(cipherTxt []byte,privateKey []byte) []byte {
	block,_:= pem.Decode(privateKey)

	priv,_:= x509.ParsePKCS1PrivateKey(block.Bytes)

	bits,_ := rsa.DecryptPKCS1v15(rand.Reader, priv, cipherTxt)

	return bits
}