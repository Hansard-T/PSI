package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"golang.org/x/crypto/hkdf"
	"io"
	"math/big"
)

func KDF(S *big.Int) []byte {
	// 将 S 转换为字节数组
	sBytes := S.Bytes()

	// 定义 salt（如果需要的话）
	salt := []byte("salt") // 可以更改为您自己的 salt

	// 定义 info（如果需要的话）
	info := []byte("info") // 可以更改为您自己的 info

	// 定义所需的密钥长度
	keyLength := 32 // 更改为所需的长度

	// 使用 HKDF 函数生成密钥
	hkdfInstance := hkdf.New(sha256.New, sBytes, salt, info)
	key := make([]byte, keyLength)
	_, err := io.ReadFull(hkdfInstance, key)
	if err != nil {
		panic(err)
	}

	return key
}

// SeEnc 将结构体或数据加密为密文，包含 nonce
func SeEnc(key []byte, plaintext interface{}) ([]byte, error) {
	// 将结构体或数据序列化为字节切片
	data, err := json.Marshal(plaintext)
	if err != nil {
		return nil, err
	}

	// 创建一个 AES 块
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 创建一个 GCM 模式的加密器
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 生成一个随机的 nonce（一次性数字）
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	// 使用 GCM 加密模式进行加密
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	// 返回包含 nonce 的密文
	return append(nonce, ciphertext...), nil
}

func RandZq(q *big.Int) *big.Int {
	// 生成随机的[0, q)之间的整数
	randValue, _ := rand.Int(rand.Reader, q)

	return randValue
}

func RandB() int64 {
	// 生成一个随机的0或1
	randomBit, _ := rand.Int(rand.Reader, big.NewInt(2))

	// 映射0到1，1到2
	if randomBit.Int64() == 0 {
		return 1
	}
	return 2
}

func ClVch(pdata Pdata, ckey CKey, y int, id int, ad []byte, G *big.Int, q *big.Int) (int, *big.Int, []byte, *big.Int, []byte) {
	// 从 pdata 中解析出其组件
	L := pdata.L
	P := pdata.P
	h1 := pdata.H1
	h2 := pdata.H2

 	// 从 ckey 中解析出Adkey
 	adkey := ckey.Adkey

	// 使用 SE_Enc 函数对 ad 加密
	adct, _:= SeEnc(adkey, ad)
	R := H(y)
	w := make([]int, 3)  // 创建一个包含两个元素的整数切片
	w[1] = h1(y)         // 将 w1 分配给第一个元素
	w[2] = h2(y)         // 将 w2 分配给第二个元素

	// 生成随机数 Beta1、Beta2、Gamma1、Gamma2 和 b
	Beta1 := RandZq(q)
	Beta2 := RandZq(q)
	Gamma1 := RandZq(q)
	Gamma2 := RandZq(q)

	// 生成随机数 b，确保 b ∈ {1, 2}
	b := RandB()
	// 计算 Q1、S1、Q2 和 S2
	Q1 := new(big.Int).Set(Beta1)
	Q1.Mul(Q1, R)
	Q1.Add(Q1, new(big.Int).Mul(Gamma1, G))

	wb := w[b]
	w3minusb := w[3-b]

	S1 := new(big.Int).Set(Beta1)
	S1.Mul(S1, P[wb])
	S1.Add(S1, new(big.Int).Mul(Gamma1, L))

	Q2 := new(big.Int).Set(Beta2)
	Q2.Mul(Q2, R)
	Q2.Add(Q2, new(big.Int).Mul(Gamma2, G))

	S2 := new(big.Int).Set(Beta2)
	S2.Mul(S2, P[w3minusb])
	S2.Add(S2, new(big.Int).Mul(Gamma2, L))

	// 使用 KDF 函数从 S1 和 S2 中生成密钥 K1 和 K2
	K1 := KDF(S1)
	K2 := KDF(S2)

	od := OD{
		Adct: adct,
	}
	// 使用 SE_Enc 函数对 (adct, sh) 使用 K1 和 K2 加密
	ct1, _:= SeEnc(K1, od)
	ct2, _:= SeEnc(K2, od)

	// 返回结果
	return id, Q1, ct1, Q2, ct2
}