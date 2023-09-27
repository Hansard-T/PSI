package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"math/big"
)

type Hxy struct {
	x *big.Int
	y *big.Int
}

type Q struct {
	x *big.Int
	y *big.Int
}

type S struct {
	x *big.Int
	y *big.Int
}

func KDF(S S) []byte {
	// 将点 S 的 x 和 y 坐标转换为字节数组
	xBytes := S.x.Bytes()
	yBytes := S.y.Bytes()

	// 连接 x 和 y 坐标的字节数组
	concatenatedBytes := append(xBytes, yBytes...)

	// 定义 salt（如果需要的话）
	salt := []byte("salt") // 可以更改为您自己的 salt

	// 定义 info（如果需要的话）
	info := []byte("info") // 可以更改为您自己的 info

	// 定义所需的密钥长度
	keyLength := 32 // 更改为所需的长度

	// 创建一个 HMAC 实例，并使用连接后的字节数组作为消息
	hmacInstance := hmac.New(sha256.New, concatenatedBytes)
	// 如果需要，可以添加 salt
	if salt != nil {
		hmacInstance.Write(salt)
	}

	// 如果需要，可以添加 info
	if info != nil {
		hmacInstance.Write(info)
	}

	// 生成密钥
	key := make([]byte, keyLength)
	hmacInstance.Sum(key)

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

func ClVch(pdata Pdata, adkey []byte, y int, id int, ad []byte, q *big.Int) (int, Q, []byte, Q, []byte) {
	// 从 pdata 中解析出其组件
	var R Hxy
	var Q1 Q
	var Q2 Q
	var S1 S
	var S2 S
	L := pdata.L
	P := pdata.P
	h1 := pdata.H1
	h2 := pdata.H2

	// 使用 SE_Enc 函数对 ad 加密
	adct, _:= SeEnc(adkey, ad)

	R.x, R.y,_ = H(y)
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
	Q1.x, Q1.y = curve.ScalarMult(R.x, R.y, Beta1.Bytes())
	x1, y1 := curve.ScalarBaseMult(Gamma1.Bytes())
	Q1.x, Q1.y = curve.Add(Q1.x, Q1.y, x1, y1)

	wb := w[b]
	w3minusb := w[3-b]
	S1.x, S1.y = curve.ScalarMult(P[wb].x, P[wb].y, Beta1.Bytes())
	x2, y2 := curve.ScalarMult(L.x, L.y, Gamma1.Bytes())
	S1.x, S1.y = curve.Add(S1.x, S1.y, x2, y2)

	Q2.x, Q2.y = curve.ScalarMult(R.x, R.y, Beta2.Bytes())
	x3, y3 := curve.ScalarBaseMult(Gamma2.Bytes())
	Q2.x, Q2.y = curve.Add(Q2.x, Q2.y, x3, y3)

	S2.x, S2.y = curve.ScalarMult(P[w3minusb].x, P[w3minusb].y, Beta2.Bytes())
	x4, y4 := curve.ScalarMult(L.x, L.y, Gamma2.Bytes())
	S2.x, S2.y = curve.Add(S2.x, S2.y, x4, y4)

	// 使用 KDF 函数从 S1 和 S2 中生成密钥 K1 和 K2
	K1 := KDF(S1)
	K2 := KDF(S2)

	// 使用 SE_Enc 函数对 (adct, sh) 使用 K1 和 K2 加密
	ct1, _:= SeEnc(K1, adct)
	ct2, _:= SeEnc(K2, adct)

	// 返回结果
	return id, Q1, ct1, Q2, ct2
}