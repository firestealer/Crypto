package EnCrypto

import "bytes"

type Cry struct {
	Data []byte
}


// 加密方法
func (cry *Cry)EnCrypt(key []byte) []byte {
	return nil
}

//解密方法
func (cry *Cry)Decrypt(cipherTxt []byte,key []byte) []byte {
	return nil
}


//PKCS5Unpadding 去码
func (cry *Cry)PKCS5UnPadding(cipherTxt []byte,blockSize int) []byte {
	pad := blockSize-len(cipherTxt)%blockSize
	padArr := bytes.Repeat([]byte{byte(pad)}, pad)
	return  append(cipherTxt, padArr...)
}

//实现PKCS5Padding补码
func (cry *Cry)PKCS5Padding(data [] byte) []byte {
	//计算准备添加的数字
	padding := 5 - len(data)%5
	//55555
	padTxt := bytes.Repeat([]byte{byte(padding)}, padding)
	//叠加两个数组
	var byteTxt = append(data, padTxt...)
	return byteTxt
}


//PKCS7Unpadding 去码
func (cry *Cry)PKCS7Padding(org []byte, blockSize int) []byte  {

	pad := blockSize-len(org)%blockSize
	padArr := bytes.Repeat([]byte{byte(pad)}, pad)
	return  append(org, padArr...)

}

//实现PKCS7Padding补码
func (cry *Cry)PKCS7UnPadding(cryptText []byte) []byte  {

	length := len(cryptText)
	lastByte := cryptText[length - 1]
	return cryptText[:length-int(lastByte)]

}



