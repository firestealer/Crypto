package EnCrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type AES struct {
	Cry
	Mode int
}

//ECB已经废弃
const (
	CBC = iota
	CFB
	OFB
	CTR
)


//AES 密钥长度 只能是 16、24、32 字节
func (a *AES)EnCrypt(key []byte) []byte {

	switch a.Mode {
		case CBC:
			return a.CBCEnCrypt(key)
		case CFB:
			return a.CFBEnCrypt(key)
		case OFB:
			return a.OFBEnCrypt(key)
		case CTR:
			return a.CTREnCrypt(key)
		default:
			return a.CTREnCrypt(key)
	}

	return nil
}

//解密方法
func (a *AES)Decrypt(cipherTxt []byte,key []byte) []byte {

	switch a.Mode {
		case CBC:
			return a.CBCDeCrypt(cipherTxt, key)
		case CFB:
			return a.CFBDeCrypt(cipherTxt, key)
		case OFB:
			return a.OFBDeCrypt(cipherTxt, key)
		case CTR:
			return a.CTRDeCrypt(cipherTxt, key)
		default:
			return a.CTRDeCrypt(cipherTxt, key)
	}
	return nil
}

//以下是私有方法
//加密
func (a *AES)CBCEnCrypt(key []byte) []byte  {

	plaintext := a.PKCS7Padding(a.Data, aes.BlockSize)

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	if len(plaintext)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext
}

func (a *AES)CFBEnCrypt(key []byte) []byte  {
	//校验密钥
	block,_ := aes.NewCipher(key)

	//拆分iv和密文
	cipherText := make([]byte, aes.BlockSize + len(a.Data))

	iv := cipherText[:aes.BlockSize]

	//向iv切片数组初始化 reader（随机内存流）
	io.ReadFull(rand.Reader, iv)

	//设置加密模式CFB
	stream := cipher.NewCFBEncrypter(block,iv)

	//加密
	stream.XORKeyStream(cipherText[aes.BlockSize:], a.Data)

	return  cipherText
}

func (a *AES)OFBEnCrypt(key []byte) []byte  {
	//校验密钥
	block,_ := aes.NewCipher(key)

	cipherText := make([]byte, aes.BlockSize + len(a.Data))

	iv := cipherText[:aes.BlockSize]

	//向iv切片数组初始化 reader（随机内存流）
	io.ReadFull(rand.Reader, iv)

	//设置加密模式CFB
	stream := cipher.NewOFB(block,iv)

	//加密
	stream.XORKeyStream(cipherText[aes.BlockSize:], a.Data)

	return  cipherText
}

func (a *AES)CTREnCrypt(key []byte) []byte  {
	//校验密钥
	block,_ := aes.NewCipher(key)

	cipherText := make([]byte, aes.BlockSize + len(a.Data))

	iv := cipherText[:aes.BlockSize]

	//向iv切片数组初始化 reader（随机内存流）
	io.ReadFull(rand.Reader, iv)

	//设置加密模式CTR
	stream := cipher.NewCTR(block,iv)

	//加密
	stream.XORKeyStream(cipherText[aes.BlockSize:], a.Data)

	return  cipherText
}





//解密

func (a *AES)CBCDeCrypt(cipherTxt []byte,key []byte) []byte  {

	ciphertext := cipherTxt;
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	//ciphertext = a.PKCS7UnPadding(ciphertext)
	return ciphertext
}

func (a *AES)CFBDeCrypt(cipherTxt []byte,key []byte) []byte  {
	//校验密钥
	block,_ := aes.NewCipher(key)

	//拆分iv 和密文
	iv := cipherTxt[:aes.BlockSize]
	cipherText := cipherTxt[aes.BlockSize:]


	//设置解密模式
	stream := cipher.NewCFBDecrypter(block, iv)

	var des = make([]byte, len(cipherText))

	//解密
	stream.XORKeyStream(des, cipherText)

	return des
}

func (a *AES)OFBDeCrypt(cipherTxt []byte,key []byte) []byte  {
	//校验密钥
	block,_ := aes.NewCipher(key)

	//拆分iv 和 密文
	iv := cipherTxt[:aes.BlockSize]
	plaintxt := make([]byte, len(cipherTxt)-aes.BlockSize)


	//设置解密模式
	stream := cipher.NewOFB(block, iv)

	//解密
	stream.XORKeyStream(plaintxt, cipherTxt[aes.BlockSize:])

	return plaintxt
}

func (a *AES)CTRDeCrypt(cipherTxt []byte,key []byte) []byte  {
	//校验密钥
	block,_ := aes.NewCipher(key)

	//拆分iv 和 密文
	iv := cipherTxt[:aes.BlockSize]
	plaintxt := make([]byte, len(cipherTxt)-aes.BlockSize)


	//设置解密模式
	stream := cipher.NewCTR(block, iv)

	//解密
	stream.XORKeyStream(plaintxt, cipherTxt[aes.BlockSize:])

	return plaintxt
}

