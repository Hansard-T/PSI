package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"testing"
	"time"
)

var alltime time.Duration

func BenchmarkMyFunction(b *testing.B) {
	b.N = 10
	// 打开CSV文件
	for j := 0; j < b.N; j++ {
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
				GeneID:          atoi(line[0]),
				AssociatedGenes: line[1],
				RelatedGenes:    line[2],
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
				Adct:      adct,
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
		U := X

		data := "C1833692"       // 字符串
		byteData := []byte(data) // 转换为 []byte
		// 调用 SePost 生成 pdata 和 alpha

		pdata, alpha := SePost(X)

		idList := []int{}
		mList := []int{}
		adList := [][]byte{}
		numUsers := 1 //用户数

		wg.Add(numUsers)

		for i := 1; i <= numUsers; i++ {
			go func(userID int) {
				defer wg.Done()

				// 生成 ckey 并获取时间
				ckey := ClInit(pdata, U) // 这里使用 pdata 和 U

				id, Q1, ct1, Q2, ct2 := ClVch(pdata, ckey, X[userID-1], userID, byteData, q)
				vouch := Vouch{
					Id:  id,
					Q1:  Q1,
					Ct1: ct1,
					Q2:  Q2,
					Ct2: ct2,
				}
				SeSTime := time.Now()
				SeCollect(alpha, vouch, &idList, &mList, &adList)
				err := SeDec(ckey.Adkey, adList[0], &byteData)
				elapsed := time.Since(SeSTime)
				mu.Lock()
				totalTime += elapsed
				mu.Unlock()
				if err != nil {
					fmt.Printf("User %d: Error during SeDec: %v\n", userID, err)
				}
				for _, adct := range adctList {
					if adct.ConceptID == string(byteData) && byteData != nil {
						fmt.Println("Match successful!")
						fmt.Printf("User %d: You might have %s\n", userID, adct.DiseaseName)
					}
				}
			}(i)
		}
		alltime += totalTime / time.Duration(numUsers)
		wg.Wait()
		fmt.Println("elapsed time:", totalTime)
		fmt.Printf("Average server working hours: %v\n", totalTime/time.Duration(numUsers))
	}
	fmt.Println("alltime:", alltime/time.Duration(b.N))
}