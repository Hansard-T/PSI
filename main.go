package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"time"
)

var q *big.Int
var G *big.Int

func init() {
	// 在 init 函数中为全局变量赋值
	q, _ = rand.Prime(rand.Reader, 2048)
	// 计算 (q-1)/2
	pMinus1Div2 := new(big.Int).Rsh(q, 1)

	// 寻找一个生成元 G
	for G == nil {
		// 生成一个随机整数 candidate 在 [2, q-1] 范围内
		candidate, _ := rand.Int(rand.Reader, new(big.Int).Sub(q, big.NewInt(2)))

		// 计算 candidate^((q-1)/2) % q
		result := new(big.Int).Exp(candidate, pMinus1Div2, q)

		// 如果结果不等于 1，candidate 是生成元
		if result.Cmp(big.NewInt(1)) != 0 {
			G = candidate
		}
	}
}

func H(y int) *big.Int {
	// 将输入转换为字节数组
	inputBytes := []byte(fmt.Sprintf("%d", y))

	// 计算输入的 SHA-256 哈希值
	hash := sha256.Sum256(inputBytes)

	// 将哈希值转换为 *big.Int
	hashInt := new(big.Int)
	hashInt.SetBytes(hash[:])

	// 将哈希值模 q，确保在 [1, q-1] 范围内
	hashInt.Mod(hashInt, q)

	// 将结果加 1，以确保在 [1, q-1] 范围内
	hashInt.Add(hashInt, big.NewInt(1))

	return hashInt
}

func main() {
	startTime := time.Now()
	// 创建一个示例 pdata
	//X := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100}
	X := generateX()
	fmt.Println("X: ", X)
	// 创建一个示例 U（这里使用一些整数作为示例）
	U := make([]int, 1000)
	for i := 1; i <= 1000; i++ {
		U[i-1] = i
	}

	data := "Hello, world!" // 字符串
	byteData := []byte(data) // 转换为 []byte
	fmt.Println("ad:", string(byteData))
	// 调用 SePost 生成 pdata 和 alpha
	pdata, alpha := SePost(X)

	// 调用 ClInit 生成 ckey
	ckey := ClInit(pdata,  U)

	id, Q1, ct1, Q2, ct2 := ClVch(pdata, ckey, 500, "1", byteData, G, q)
	vouch := Vouch{
		Id:  id,
		Q1:  Q1,
		Ct1: ct1,
		Q2:  Q2,
		Ct2: ct2,
	}
	idList, mList, adList := SeCollect(alpha, vouch)
	err := SeDec(ckey.Adkey, adList[0], &byteData)
	if err != nil {
		return 
	}

	endTime := time.Now()
	elapsedTime := endTime.Sub(startTime)

	fmt.Println("idList:", idList)
	fmt.Println("mList:", mList)
	fmt.Println("adList:", adList)
	fmt.Println("ad:", string(byteData))
	fmt.Printf("程序执行时间: %v\n", elapsedTime)
}