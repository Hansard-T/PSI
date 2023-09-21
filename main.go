package main

import (
	"crypto/rand"
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
var G *big.Int
var mu sync.Mutex
var totalTime time.Duration
var wg sync.WaitGroup
type ADCTList []ADCT

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

	// 遍历 diseaseDataList 并提取 ADCT 部分
	adctList := ADCTList{}
	for _, diseaseData := range diseaseDataList {
		adctList = append(adctList, diseaseData.Adct)
	}
	// 创建一个示例 U（这里使用一些整数作为示例）
	U := make([]int, 1000)
	for i := 1; i <= 1000; i++ {
		U[i-1] = i
	}

	data := "C1833692" // 字符串
	byteData := []byte(data) // 转换为 []byte
	// 调用 SePost 生成 pdata 和 alpha

	pdata, alpha := SePost(X)

	idList := []int{}
	mList := []int{}
	adList := [][]byte{}
	numUsers := 1000 //用户数

	wg.Add(numUsers)

	for i := 1; i <= numUsers; i++ {
		go func(userID int) {
			defer wg.Done()

			// 生成 ckey 并获取时间
			ckey := ClInit(pdata, U) // 这里使用 pdata 和 U

			id, Q1, ct1, Q2, ct2 := ClVch(pdata, ckey, X[userID-1], userID, byteData, G, q)
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
			mu.Lock()
			totalTime += elapsed
			mu.Unlock()
			if err != nil {
				fmt.Printf("User %d: Error during SeDec: %v\n", userID, err)
			}
			fmt.Println("Match successful!")
			for _, adct := range adctList {
				if adct.ConceptID == string(byteData) && byteData != nil{
					fmt.Printf("User %d: You might have %s\n",userID , adct.DiseaseName)
				}
			}
		}(i)
	}

	wg.Wait()
	fmt.Println("elapsed time:", totalTime)
	fmt.Printf("Average server working hours: %v\n", totalTime/time.Duration(numUsers))
}