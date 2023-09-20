package main

import (
	"fmt"
	"testing"
)

func BenchmarkMyFunction(b *testing.B) {
	for j := 0; j < b.N; j++ {
		X := generateX()

		// 创建一个示例 U（这里使用一些整数作为示例）
		U := make([]int, 1000)
		for i := 1; i <= 1000; i++ {
			U[i-1] = i
		}

		data := "Hello, world!"  // 字符串
		byteData := []byte(data) // 转换为 []byte
		// 调用 SePost 生成 pdata 和 alpha

		pdata, alpha := SePost(X)

		idList := []int{}
		mList := []int{}
		adList := [][]byte{}

		// 生成 ckey 并获取时间
		ckey := ClInit(pdata, U) // 这里使用 pdata 和 U

		// 调用 ClVch 生成 id, Q1, ct1, Q2, ct2 并获取时间
		//y := generateY()
		id, Q1, ct1, Q2, ct2 := ClVch(pdata, ckey, X[0], 1, byteData, G, q)
		// 使用生成的数据执行其他操作
		vouch := Vouch{
			Id:  id,
			Q1:  Q1,
			Ct1: ct1,
			Q2:  Q2,
			Ct2: ct2,
		}
		SeCollect(alpha, vouch, &idList, &mList, &adList)
		err := SeDec(ckey.Adkey, adList[len(adList)-1], &byteData)
		if err != nil {
			fmt.Printf("User %d: Error during SeDec: %v\n", 1, err)
		}
	}
}