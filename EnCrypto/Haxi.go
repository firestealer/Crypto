package EnCrypto

import (
	"crypto/md5"
	"encoding/hex"
	"crypto/sha256"
	"os"
	"io"
	"golang.org/x/crypto/ripemd160"
)

func Md5(data string) string  {

	mes := []byte(data)
	// 1. 使用系统的包实现
	// 密文为16进制的数字 16 *8 = 128位
	//by := md5.Sum(mes)

	// 2. 第二种写法
	m := md5.New()
	m.Write(mes)
	//将字节数组转换成字符串
	s:= hex.EncodeToString(m.Sum(nil))
	return s
}

func Sha256(data string) string {

	// 32字节 通用在公链中 32 * 8 = 256 位
	//// 2. 第一种写法
	//by := sha256.Sum256([]byte(data))
	//s := fmt.Sprintf("%x", by)
	//fmt.Println(s)

	// 2. 第二种写法
	m := sha256.New()
	m.Write([]byte(data))
	s := hex.EncodeToString(m.Sum(nil))
	return s

}

func Sha256WithFile(path string) string  {
	//对文件中的数据进行加密
	file, _ := os.Open("test.txt")
	h := sha256.New()
	//将file copy到 h中
	io.Copy(h, file)
	s := h.Sum(nil)

	return hex.EncodeToString(s)

}

//需要用到三方库 crypto
func Ripem160(data string) string  {

	rip := ripemd160.New()
	rip.Write([]byte(data))
	s := hex.EncodeToString(rip.Sum(nil))
	return s
}
