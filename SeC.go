package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"math/big"
	"math/rand"
	"time"
)

type Vouch struct {
	Id  int
	Q1  *big.Int
	Ct1 []byte
	Q2  *big.Int
	Ct2 []byte
}

type OD struct {
	Adct []byte
}

type IM struct {
	I int
	Match int
}

func generateY() int {
	rand.Seed(time.Now().UnixNano()) // 使用当前时间作为随机数种子

	// 生成1000以内的随机数
	y := rand.Intn(1000)
	return y
}

func generateX() []int {
	rand.Seed(time.Now().UnixNano()) // 设置随机数种子，以确保每次运行都产生不同的随机数

	// 创建一个 map 用于存储已生成的数字，以确保不重复
	uniqueNumbers := make(map[int]bool)

	// 创建一个切片用于存储不重复的数字
	uniqueSlice := make([]int, 0)

	for len(uniqueSlice) < 1000 {
		// 生成一个随机数
		randomNumber := rand.Intn(1000) + 1

		// 检查随机数是否已经存在于 map 中，如果不存在，则添加到切片和 map 中
		if !uniqueNumbers[randomNumber] {
			uniqueNumbers[randomNumber] = true
			uniqueSlice = append(uniqueSlice, randomNumber)
		}
	}
	return uniqueSlice
}

func SeDec(key, ciphertext []byte, plaintext interface{}) error {
	// 创建一个 AES 块
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// 创建一个 GCM 模式的解密器
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// 获取 nonce 大小
	nonceSize := gcm.NonceSize()
	// 提取 nonce 和实际的密文
	if ciphertext == nil {
		return errors.New("ciphertext is nil, not a match")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	// 使用 GCM 解密模式进行解密
	data, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	// 反序列化解密后的字节切片为原始结构体
	if err := json.Unmarshal(data, plaintext); err != nil {
		return err
	}

	return nil
}

func SeCollect(alpha *big.Int, vouch Vouch, idList *[]int, mList *[]int, adList *[][]byte) {
	id := vouch.Id
	Q1 := vouch.Q1
	ct1 := vouch.Ct1
	Q2 := vouch.Q2
	ct2 := vouch.Ct2
	S1 := new(big.Int).Mul(alpha, Q1)
	S2 := new(big.Int).Mul(alpha, Q2)
	K1 := KDF(S1)
	K2 := KDF(S2)

	var decrypted1 OD
	var decrypted2 OD
	M1 := SeDec(K1, ct1, &decrypted1)
	M2 := SeDec(K2, ct2, &decrypted2)

	// 初始化变量 i 和 match
	im := IM{
		I: 0,
		Match: 0,
	}
	// 根据条件设置 i 和 match
	if M1 == nil && M2 != nil {
		im.I = 1
		im.Match = 1
	} else if M1 != nil && M2 == nil {
		im.I = 2
		im.Match = 1
	}

	*idList = append(*idList, id)
	*mList = append(*mList, im.Match)
	if im.I == 1 && im.Match == 1 {
		*adList = append(*adList,decrypted1.Adct)
	}else if im.I == 2 && im.Match == 1 {
		*adList = append(*adList,decrypted2.Adct)
	}else{
		*adList = append(*adList, nil)
	}
}