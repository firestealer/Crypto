package main

import (
	"fmt"
	"encoding/hex"
	"goDemo/EnCrypto/EnCrypto"
)

var privateKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCQRttulLHUA3DkckkD7Bco5fY0nBDe8RlDZuIV2pu3Ry4qgZNL
d7OiYkgTcow0LIXeW4HpLJZI9oxCS3p4Y+w3AAWOjmpPXZfc3NAiW0iboLa6qld0
TfWogHurC2ArSkONEGzGzdgZrBUDGt8s+sdKmRxxLjPiWq1HQhmywNv3BQIDAQAB
AoGAPKJ64Ct/3QGhNXFOfGaBiT+0TIH2mSusmWYoyFR6svkoTtbsJ4BkL2+sqPew
MtEvZbcBjxSdCIcNhWMhUm10PTur6mOhcAABxTjdFEbIbJRHVlrsDYkyGPLOaaem
UOZeTAtnNQVAnbQpXIwLmwkSSmbJPyvFc534/c7fMkHg1RUCQQDAL5kgijYHox/1
ybqKoBxKrlIjwCpgJ7XIIXRu+AyCLNvzRRviIGGQQ5Q605hSKB+j/6lYKO/kjiNA
Jh5pYPr7AkEAwC7VLAjLQeHD/QD8SaEwQr9WgE3WxF0LuS+AI767Kluw2N2RSDhw
nfNaBhFe1j7mUQLP4C/HIFFjmi1+HiQ1/wJBAKHXM3dAjJFP4HkmAO3+OPT26Xrr
t4OzzRQUgC12u2ngBvVMrFd3d1F6Z1hGmc4Ntd9wS5ZPGv14aNz7fL63CYMCQQC9
T+TxwZ/nwCu+GLBtH3lY5v6g2QyM1lNsEpyZmZLpwPTOTESG7gIRtdyiSY4wYjmi
57A6WRZAgawp/lJUArulAkA3LKFGfViQVjRWkoIYN65R87L6DohHH1LXVg4wUUtF
IXwDFSCbHsQko+vzIlBtSXr5/hO+1CkZLtI0tisWHPCi
-----END RSA PRIVATE KEY-----`)

var publicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCQRttulLHUA3DkckkD7Bco5fY0
nBDe8RlDZuIV2pu3Ry4qgZNLd7OiYkgTcow0LIXeW4HpLJZI9oxCS3p4Y+w3AAWO
jmpPXZfc3NAiW0iboLa6qld0TfWogHurC2ArSkONEGzGzdgZrBUDGt8s+sdKmRxx
LjPiWq1HQhmywNv3BQIDAQAB
-----END PUBLIC KEY-----`)

func main()  {


	testDES()

	testAES()

	testRSA()



}

func testDES()  {
	//des
	fmt.Println("------------- des --------------")
	des := EnCrypto.DES{}
	des.Data = []byte("i am des")
	key := []byte("a b c d ")

	ent := des.EnCrypt(key)
	fmt.Println("加密",hex.EncodeToString(ent))
	fmt.Println("解密",string(des.Decrypt(ent, key)))
}

func testAES()  {
	//aes
	fmt.Println("------------- aes cbc--------------")
	aes := EnCrypto.AES{}
	//CBC模式的 data 的长度需要为16的倍数
	aes.Data = []byte("cbcgsd dsfgsdfqq")
	aes.Mode = EnCrypto.CBC
	key := []byte("6368616e676520746869732070617373")
	ent := aes.EnCrypt(key)
	fmt.Println("加密",hex.EncodeToString(ent))
	fmt.Println("解密",string(aes.Decrypt(ent, key)), len(string(aes.Decrypt(ent, key))))


	fmt.Println("------------- aes cfb--------------")
	aes.Data = []byte("i am aes cfb")
	aes.Mode = EnCrypto.CFB
	key = []byte("1234567890123456")
	key = []byte("1234567890asdfgh12345678")
	key = []byte("12345678901234561234567890123456")
	ent = aes.EnCrypt(key)
	fmt.Println("加密",hex.EncodeToString(ent))
	fmt.Println("解密",string(aes.Decrypt(ent, key)), len(string(aes.Decrypt(ent, key))))


	fmt.Println("------------- aes ofb--------------")
	aes.Data = []byte("i am aes ofb")
	aes.Mode = EnCrypto.OFB
	key = []byte("12345678901234561234567890123456")
	ent = aes.EnCrypt(key)
	fmt.Println("加密",hex.EncodeToString(ent))
	fmt.Println("解密",string(aes.Decrypt(ent, key)), len(string(aes.Decrypt(ent, key))))

	fmt.Println("------------- aes ctr--------------")
	aes.Data = []byte("i am aes ctr")
	aes.Mode = EnCrypto.CTR
	key = []byte("12345678901234561234567890123456")
	ent = aes.EnCrypt(key)
	fmt.Println("加密",hex.EncodeToString(ent))
	fmt.Println("解密",string(aes.Decrypt(ent, key)), len(string(aes.Decrypt(ent, key))))
}

func testRSA()  {

	fmt.Println("-------------rsa 加密 解密--------------")
	r := EnCrypto.RSA{}
	r.Data = []byte("i am rsa")

	ent := r.EnCrypt(publicKey)

	fmt.Println("加密",hex.EncodeToString(ent))


	ori := r.Decrypt(ent, privateKey)
	fmt.Println("解密",string(ori))
}