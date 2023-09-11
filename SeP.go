package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/spaolacci/murmur3"
	"math/big"
)

const (
	maxAttempts = 100000000 // 最大迁移尝试次数
)

type Pdata struct {
	L   *big.Int
	N0  int
	P   []*big.Int
	H1  func(int) int
	H2  func(int) int
}

// MkHT1 用于生成哈希表大小 n0 和两个哈希函数 h1, h2
func MkHT1(sizeX int) (int, func(int) int, func(int) int) {
	// 假设哈希表的大小 n0 是集合大小的四倍
	n0 := sizeX * 4

	h1 := func(x int) int {
		// 将整数 x 转换为 4 个字节的字节数组
		xBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(xBytes, uint32(x))

		// 使用 MurmurHash 3 计算哈希值
		hash := murmur3.Sum32(xBytes)
		return int(hash % uint32(n0-1)) + 1
	}

	h2 := func(x int) int {
		// 将整数 (x + 1) 转换为 4 个字节的字节数组
		xPlusOneBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(xPlusOneBytes, uint32((x + 1)*h1(x)))

		// 使用 MurmurHash 3 计算哈希值
		hash := murmur3.Sum32(xPlusOneBytes)
		return int(hash % uint32(n0-1)) + 1
	}

	return n0, h1, h2
}

// MkHT2 根据集合 X 和两个哈希函数 h1 和 h2 生成哈希表 T
func MkHT2(X []int, h1, h2 func(int) int, n0 int) []int {
	// 使用所有值为 -1 初始化哈希表 T，表示空桶
	T := make([]int, n0)
	for i := range T {
		T[i] = -1
	}

	occupied := 0 // 记录占用槽位的数量

	for _, x := range X {
		attempts := 0
		pos1 := h1(x)
		// 尝试将元素 x 插入哈希桶
		for {
			if attempts >= maxAttempts  || occupied >= n0 {
				// 如果达到最大尝试次数或表已满，停止插入并输出一条错误信息
				fmt.Println("插入失败，哈希表已满。")
				return T
			}

			if T[pos1] == -1 {
				// 如果当前位置为空，将 x 插入该位置
				T[pos1] = x
				occupied++
				break
			}

			// 如果当前位置不为空，尝试将元素迁移到其他哈希桶
			x, T[pos1] = T[pos1], x
			attempts++
			if pos1 == h1(x) {
				// 如果迁移回到原始位置，使用第二个哈希函数
				pos1 = h2(x)
			} else {
				// 否则返回原始位置
				pos1 = h1(x)
			}
		}
	}
	fmt.Println("T:", T)
	return T
}

func SePost(X []int) (Pdata, *big.Int) {
	n0, h1, h2 := MkHT1(len(X))
	T := MkHT2(X, h1, h2, n0)

	// 随机生成一个大于等于 1，小于 q/G 的随机整数
	alpha, _ := rand.Int(rand.Reader, new(big.Int).Div(q, G))

	// 将 alpha 增加 1，确保它在 [1, q-1] 范围内
	alpha.Add(alpha, big.NewInt(1))
	P := make([]*big.Int, n0)

	for i := 0; i < n0; i++ {
		if T[i] != -1 {
			// 如果 T[i] 不为空，则计算 Pi = α * H(T[i])
			P[i] = new(big.Int).Mul(alpha, H(T[i]))
		} else {
			// 否则 Pi 随机选择一个不为 0 的值
			randValue, _ := rand.Int(rand.Reader, new(big.Int).Sub(q, big.NewInt(1)))
			one := big.NewInt(1)
			randValue.Add(randValue, one) // 加一确保不为 0
			P[i] = randValue
		}
	}

	// 计算 L
	L := new(big.Int).Mul(alpha, G)

	// 创建 pdata 结构体并设置字段
	pdata := Pdata{
		L:    L,
		N0:   n0,
		P:    P,
		H1:   h1,
		H2:   h2,
	}

	return pdata, alpha
}