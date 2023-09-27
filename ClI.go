package main

import (
	"crypto/rand"
	"math/big"
)

const (
	k = 256
)

type CKey struct {
	Adkey []byte
}
// Valid 验证 pdata 是否有效
func Valid(pdata Pdata, U []int) bool {
	L := pdata.L
	P := pdata.P
	h1 := pdata.H1
	h2 := pdata.H2

	// 要求 L 必须在 G \ {0} 中
	zero := big.NewInt(0)
	if !curve.IsOnCurve(L.x, L.y) || L.x.Cmp(big.NewInt(0)) == 0 || L.y.Cmp(big.NewInt(0)) == 0 {
		return false
	}

	// 要求 P1, ..., Pn0 必须在 G \ {0} 中且各不相同
	uniqueP := make(map[string]bool)
	for _, p := range P {
		if !curve.IsOnCurve(p.x, p.y) || p.x.Cmp(zero) == 0 || p.x.Cmp(q) >= 0 || uniqueP[p.x.String()] {
			return false
		}
		uniqueP[p.x.String()] = true
	}

	// 要求 h1 和 h2 必须是从 U 到 [1..n0] 的映射
	n0 := len(P)
	for _, x := range U {
		if h1(x) < 1 || h1(x) > n0 || h2(x) < 1 || h2(x) > n0  {
			return false
		}
	}

	// 所有检查都通过，返回 true
	return true
}

func ClInit(pdata Pdata ,U []int) []byte {
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

	return adkey
}