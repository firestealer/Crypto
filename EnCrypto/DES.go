package EnCrypto

import (
	"ketang/mimaxue/06_26/MyCript/DES"
	"crypto/cipher"
	"crypto/des"
)

type DES struct {
	Cry
}

//key长度必须为8位
// 加密方法
func (d *DES)EnCrypt(key []byte) []byte {
	//校验密钥
	block, _ := des.NewCipher(key)
	//设置补码
	origData := MyDES.PKCS5Padding(d.Data, block.BlockSize())
	//设置CBC加密模式
	blockMode := cipher.NewCBCEncrypter(block, key)

	//加密明文
	cryppTxt := make([]byte, len(origData))

	blockMode.CryptBlocks(cryppTxt, origData)

	return cryppTxt
}

//解密方法
func (d *DES)Decrypt(cipherTxt []byte,key []byte) []byte {
	//校验key的有效性
	block,_:=des.NewCipher(key)
	//通过CBC模式解密
	blockMode:=cipher.NewCBCDecrypter(block,key)

	//实现解密
	origData:=make([]byte,len(cipherTxt))
	blockMode.CryptBlocks(origData,cipherTxt)

	//去码
	origData = MyDES.PKCS5UnPadding(origData)
	return origData
}