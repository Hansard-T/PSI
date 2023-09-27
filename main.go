package main

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"sync"
	"time"
)

var q *big.Int
var mu sync.Mutex
var totalTime time.Duration
var wg sync.WaitGroup
type ADCTList []ADCT
var curve elliptic.Curve

type GeneInfor struct {
	GeneID	int
	AssociatedGenes string
	RelatedGenes string
}

type ADCT struct {
	ConceptID	string
	DiseaseName	string
	SourceName	string
	SourceID	string
	DiseaseMIM	string
}

type DiseaseData struct {
	Geneinfor	GeneInfor
	Adct	ADCT
}

func init() {
	// 在 init 函数中为全局变量赋值
	curve = elliptic.P521()
	q = curve.Params().P
}

func H(y int) (*big.Int, *big.Int, error) {
	// 将输入转换为字节数组
	inputBytes := []byte(fmt.Sprintf("%d", y))

	// 计算输入的 SHA-256 哈希值
	hash := sha256.Sum256(inputBytes)

	// 将哈希值转换为 *big.Int
	hashInt := new(big.Int).SetBytes(hash[:])

	// 计算 x1，确保在 [1, p-1] 范围内
	x1 := new(big.Int).Set(hashInt)
	x1.Mod(x1, curve.Params().P)

	// 计算 y^2 模 p-521
	ySquared := new(big.Int)
	ySquared.Exp(x1, big.NewInt(3), nil)
	ySquared.Sub(ySquared, big.NewInt(3).Mul(x1, big.NewInt(3)))
	ySquared.Add(ySquared, curve.Params().B)
	ySquared.Mod(ySquared, curve.Params().P)

	// 尝试计算 ModSqrt
	y1 := ModSqrt(ySquared, curve.Params().P)

	// 创建椭圆曲线上的点
	x1, y1 = curve.ScalarBaseMult(x1.Bytes())

	return x1, y1, nil
}

// ModSqrt 计算给定值的平方根（模 p）
func ModSqrt(a, p *big.Int) *big.Int {
	// 计算 a^(p+1)/4
	exp := new(big.Int).Add(p, big.NewInt(1))
	exp.Div(exp, big.NewInt(4))
	result := new(big.Int).Exp(a, exp, p)

	// 检查是否为平方根
	square := new(big.Int).Exp(result, big.NewInt(2), p)
	if square.Cmp(a) == 0 {
		return result
	}
	return nil // 无效的平方根
}

func atoi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func removeDuplicates(geneInfoList []GeneInfor) []GeneInfor {
	// 创建一个 map 用于跟踪已经出现的元素
	seen := make(map[GeneInfor]bool)

	// 创建一个新的空列表，用于存储去重后的元素
	uniqueList := []GeneInfor{}

	// 遍历原始列表，进行去重操作
	for _, geneInfo := range geneInfoList {
		// 如果当前元素不在 map 中，表示尚未出现过，将其添加到新列表中
		if !seen[geneInfo] {
			uniqueList = append(uniqueList, geneInfo)

			// 标记当前元素为已经出现
			seen[geneInfo] = true
		}
	}

	return uniqueList
}

func main() {
	// 打开CSV文件
	file, err := os.Open("/Users/tangxianning/Downloads/input.csv")
	if err != nil {
		fmt.Println("无法打开CSV文件:", err)
		return
	}

	// 创建CSV reader
	reader := csv.NewReader(file)

	// 读取CSV文件中的所有行
	lines, err := reader.ReadAll()
	if err != nil {
		fmt.Println("无法读取CSV文件:", err)
		return
	}

	// 遍历每一行并解析为 DiseaseData 结构体
	var diseaseDataList []DiseaseData
	var geneInfoList []GeneInfor
	for _, line := range lines {
		geneInfor := GeneInfor{
			GeneID:         atoi(line[0]),
			AssociatedGenes: line[1],
			RelatedGenes:   line[2],
		}
		adct := ADCT{
			ConceptID:   line[3],
			DiseaseName: line[4],
			SourceName:  line[5],
			SourceID:    line[6],
			DiseaseMIM:  line[7],
		}

		diseaseData := DiseaseData{
			Geneinfor: geneInfor,
			Adct:     adct,
		}
		diseaseDataList = append(diseaseDataList, diseaseData)
		geneInfoList = append(geneInfoList, geneInfor)
	}

	uniqueList := removeDuplicates(geneInfoList)
	// 遍历 geneInfoList 并获取信息，并将转换后的结果存储在 X 中
	var X []int
	for _, geneInfo := range uniqueList {
		x := convertGeneInfoToX(geneInfo)
		X = append(X, x)
	}

	U := X

	data := "C1833692" // 也许可以是个人的姓名或者其他身份信息，只有在匹配上时，才会获得这些消息
	mu.Lock()
	byteData := []byte(data) // 修改 byteData
	mu.Unlock()
	// 调用 SePost 生成 pdata 和 alpha

	pdata, alpha := SePost(X)

	idList := []int{}
	mList := []int{}
	adList := [][]byte{}
	numUsers := 10 //用户数

	wg.Add(numUsers)
	for i := 1; i <= numUsers; i++ {
		go func(userID int) {
			defer wg.Done()

			// 生成 ckey 并获取时间
			adkey := ClInit(pdata, U) // 这里使用 pdata 和 U

			id, Q1, ct1, Q2, ct2 := ClVch(pdata, adkey, X[userID-1], userID, byteData, q)
			vouch := Vouch{
				Id:  id,
				Q1:  Q1,
				Ct1: ct1,
				Q2:  Q2,
				Ct2: ct2,
			}
			SeSTime := time.Now()
			SeCollect(alpha, vouch, &idList, &mList, &adList)
			err := SeDec(adkey, adList[0], &byteData)
			elapsed := time.Since(SeSTime)
			mu.Lock()
			totalTime += elapsed
			mu.Unlock()
			if err != nil {
				fmt.Printf("User %d: Error during SeDec: %v\n", userID, err)
			}
			fmt.Println("Match success.")
		}(i)
	}

	wg.Wait()
	fmt.Println("elapsed time:", totalTime)
	fmt.Printf("Average server working hours: %v\n", totalTime/time.Duration(numUsers))
}