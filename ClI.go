package main

import (
	"crypto/rand"
	"math/big"
)

const (
	k = 256 // 根据您的需求设置 adkey 的位数
	t = 128 // 根据您的需求设置 a1, a2, ... 的位数
)

type CKey struct {
	Adkey []byte
	//A     [][]byte
}
// Valid 验证 pdata 是否有效
func Valid(pdata Pdata, U []int) bool {
	L := pdata.L
	P := pdata.P
	h1 := pdata.H1
	h2 := pdata.H2

	// 要求 L 必须在 G \ {0} 中
	zero := big.NewInt(0)
	if L.Cmp(zero) == 0 || L.Cmp(q) >= 0 {
		return false
	}

	// 要求 P1, ..., Pn0 必须在 G \ {0} 中且各不相同
	uniqueP := make(map[string]bool)
	for _, p := range P {
		if p.Cmp(zero) == 0 || p.Cmp(q) >= 0 || uniqueP[p.String()] {
			return false
		}
		uniqueP[p.String()] = true
	}

	// 要求 h1 和 h2 必须是从 U 到 [1..n0] 的映射
	n0 := len(P)
	for _, x := range U {
		if h1(x) < 1 || h1(x) > n0 || h2(x) < 1 || h2(x) > n0 || h1(x) == h2(x) {
			return false
		}
	}

	// 所有检查都通过，返回 true
	return true
}

func ClInit(pdata Pdata ,U []int) CKey {
	// 首先验证 pdata 是否有效
	if !Valid(pdata, U) {
		panic("Invalid")
	}

	// 生成一个随机的 adkey，可以是 k 位的 0 和 1 组成的位字符串
	adkey := make([]byte, k/8)
	_, err := rand.Read(adkey)
	if err != nil {
		panic(err)
	}

	// 组合 adkey 和 a1, a2, ..., at 成为 ckey
	ckey := CKey{adkey}

	return ckey
}