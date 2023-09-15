package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"
	"time"
)

var q *big.Int
var G *big.Int
var mu sync.Mutex
var totalTime time.Duration
var wg sync.WaitGroup

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

	X := generateX()

	// 创建一个示例 U（这里使用一些整数作为示例）
	U := make([]int, 1000)
	for i := 1; i <= 1000; i++ {
		U[i-1] = i
	}

	data := "Hello, world!" // 字符串
	byteData := []byte(data) // 转换为 []byte
	// 调用 SePost 生成 pdata 和 alpha

	pdata, alpha := SePost(X)

	idList := []int{}
	mList := []int{}
	adList := [][]byte{}
	numUsers := 1000 // 512个用户

	wg.Add(numUsers)

	for i := 1; i <= numUsers; i++ {
		go func(userID int) {
			defer wg.Done()

			// 生成 ckey 并获取时间
			ckey := ClInit(pdata, U) // 这里使用 pdata 和 U

			// 调用 ClVch 生成 id, Q1, ct1, Q2, ct2 并获取时间
			//y := generateY()
			id, Q1, ct1, Q2, ct2 := ClVch(pdata, ckey, X[userID%1000], userID, byteData, G, q)
			// 使用生成的数据执行其他操作
			vouch := Vouch{
				Id:  id,
				Q1:  Q1,
				Ct1: ct1,
				Q2:  Q2,
				Ct2: ct2,
			}
			SeSTime := time.Now()
			SeCollect(alpha, vouch, &idList, &mList, &adList)
			err := SeDec(ckey.Adkey, adList[len(adList)-1], &byteData)
			elapsed := time.Since(SeSTime)
			fmt.Println("Elapsed: ", elapsed)
			mu.Lock()
			totalTime += elapsed
			mu.Unlock()
			if err != nil {
				fmt.Printf("User %d: Error during SeDec: %v\n", userID, err)
			}
		}(i)
	}

	wg.Wait()
	fmt.Println("elapsed time:", totalTime)
	fmt.Printf("Average server working hours: %v\n", totalTime/time.Duration(numUsers))
}