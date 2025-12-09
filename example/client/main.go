package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"

	cqs "github.com/ixycoder/caddy-query-signature"
)

func main() {
	// 创建签名生成器
	sg := cqs.NewSignatureGenerator("another-secret")
	sg.SignParam = "sign"
	sg.TimestampParam = "timestamp"

	// 准备参数
	// params := url.Values{
	// 	"action":  {"query"},
	// 	"user_id": {"1001"},
	// 	"page":    {"1"},
	// 	"size":    {"20"},
	// }
	params := url.Values{}

	// 生成带签名的URL
	signedURL, err := sg.GenerateSignature(
		"http://192.168.20.129:8080/",
		"GET",
		params,
	)

	if err != nil {
		panic(err)
	}

	fmt.Printf("Signed URL: %s\n", signedURL)

	// 直接发送请求
	resp, err := http.Get(signedURL)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Response Body: %s\n", body)
}
