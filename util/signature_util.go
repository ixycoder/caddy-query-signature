package util

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// SignatureGenerator 签名生成器
type SignatureGenerator struct {
	SecretKey      string
	SignParam      string
	TimestampParam string
	AccessKeyParam string
	ExcludeParams  []string
}

// NewSignatureGenerator 创建签名生成器
func NewSignatureGenerator(secretKey string) *SignatureGenerator {
	return &SignatureGenerator{
		SecretKey:      secretKey,
		SignParam:      "sign",
		TimestampParam: "timestamp",
		AccessKeyParam: "ak",
	}
}

// GenerateSignature 生成带签名的URL
func (sg *SignatureGenerator) GenerateSignature(baseURL, method string, params url.Values) (string, error) {
	// 添加时间戳
	if sg.TimestampParam != "" {
		params.Set(sg.TimestampParam, time.Now().Format(time.RFC3339))
	}

	// 添加访问密钥
	if sg.AccessKeyParam == "" {
		return "", fmt.Errorf("access_key_param is required")
	}
	accessKey := params.Get(sg.AccessKeyParam)
	if accessKey == "" {
		return "", fmt.Errorf("access_key is empty!")
	}

	// 构建完整URL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// 构建待签名字符串
	stringToSign := sg.buildStringToSign(params, method, parsedURL.Path, accessKey)

	// 计算签名
	signature := sg.calculateSignature(stringToSign)

	// 添加签名参数
	params.Set(sg.SignParam, signature)

	query := params.Encode()
	if parsedURL.RawQuery != "" {
		parsedURL.RawQuery = parsedURL.RawQuery + "&" + query
	} else {
		parsedURL.RawQuery = query
	}

	return parsedURL.String(), nil
}

// buildStringToSign 构建待签名字符串
func (sg *SignatureGenerator) buildStringToSign(params url.Values, method, path, accessKey string) string {
	// 按参数名排序
	var keys []string
	for k := range params {
		// 排除签名参数和不需要参与签名的参数
		if k != sg.SignParam && !sg.isExcludedParam(k) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	// 构建参数字符串
	var paramStrs []string
	for _, k := range keys {
		values := params[k]
		sort.Strings(values)
		for _, v := range values {
			paramStrs = append(paramStrs, fmt.Sprintf("%s=%s", k, v))
		}
	}

	return fmt.Sprintf("%s\n%s\n%s\n%s\n",
		method, path, strings.Join(paramStrs, "&"), accessKey)

	// return fmt.Sprintf("%s&%s&%s", method, path, strings.Join(paramStrs, "&"))
}

// calculateSignature 计算签名
func (sg *SignatureGenerator) calculateSignature(data string) string {
	h := hmac.New(sha256.New, []byte(sg.SecretKey))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// isExcludedParam 检查参数是否排除
func (sg *SignatureGenerator) isExcludedParam(param string) bool {
	for _, exclude := range sg.ExcludeParams {
		if param == exclude {
			return true
		}
	}
	return false
}

// VerifySignature 验证签名（独立验证函数）
func VerifySignature(secretKey, signParam, timestampParam, accessKeyParam string, params url.Values, method, path string) bool {
	sign := params.Get(signParam)
	if sign == "" {
		return false
	}

	accessKey := params.Get(accessKeyParam)
	if accessKey == "" {
		return false
	}

	// 移除签名参数
	params.Del(signParam)

	// 生成待签名字符串
	sg := NewSignatureGenerator(secretKey)
	sg.SignParam = signParam
	sg.TimestampParam = timestampParam
	sg.AccessKeyParam = accessKeyParam
	stringToSign := sg.buildStringToSign(params, method, path, accessKey)

	// 计算期望的签名
	expectedSign := sg.calculateSignature(stringToSign)

	return hmac.Equal([]byte(sign), []byte(expectedSign))
}
