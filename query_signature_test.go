package cqs

import (
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/ixycoder/caddy-query-signature/util"
	"go.uber.org/zap"
)

func TestQuerySignature(t *testing.T) {
	tests := []struct {
		name           string
		config         string
		path           string
		params         url.Values
		expectedStatus int
		shouldPass     bool
	}{
		{
			name: "valid signature",
			config: `query_signature {
                path /api
                secret_key "test-secret-key"
                sign_param "sig"
                timestamp_param "ts"
                expire_seconds 300
            }`,
			path: "/api/data",
			params: url.Values{
				"action": {"get"},
				"id":     {"123"},
				"ts":     {time.Now().Format(time.RFC3339)},
			},
			shouldPass: true,
		},
		{
			name: "valid signature with custom params",
			config: `query_signature {
                path /
                secret_key "test-secret-key"
				sign_param "signature"
                timestamp_param "timestamp"
                expire_seconds 300
            }`,
			path: "/456.png",
			params: url.Values{
				"timestamp": {time.Now().Format(time.RFC3339)},
			},
			shouldPass: true,
		},
		{
			name: "expired signature",
			config: `query_signature {
                path /api
                secret_key "test-secret-key"
                expire_seconds 60
            }`,
			path: "/api/data",
			params: url.Values{
				"action":    {"get"},
				"id":        {"123"},
				"timestamp": {time.Now().Add(-2 * time.Minute).Format(time.RFC3339)},
			},
			shouldPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 解析配置
			d := caddyfile.NewTestDispenser(tt.config)
			var qs QuerySignature
			if err := qs.UnmarshalCaddyfile(d); err != nil {
				t.Fatalf("failed to parse config: %v", err)
			}

			// 设置logger
			qs.logger = zap.NewNop()

			// 生成签名
			sg := util.NewSignatureGenerator("test-secret-key")
			sg.SignParam = qs.SignParam
			sg.TimestampParam = qs.TimestampParam

			signedURL, err := sg.GenerateSignature(tt.path, "GET", tt.params)
			if err != nil {
				t.Fatalf("failed to generate signature: %v", err)
			}

			// 解析URL
			parsedURL, err := url.Parse(signedURL)
			if err != nil {
				t.Fatalf("failed to parse URL: %v", err)
			}

			// fmt.Printf("Signed URL: %s\n", signedURL)
			// 创建请求
			req := httptest.NewRequest("GET", parsedURL.String(), nil)

			// 验证签名
			err = qs.verifySignature(req)

			if tt.shouldPass && err != nil {
				t.Errorf("expected pass but got error: %v", err)
			}
			if !tt.shouldPass && err == nil {
				t.Error("expected error but passed")
			}
		})
	}
}

func TestSignatureGenerator(t *testing.T) {
	sg := util.NewSignatureGenerator("test-secret")

	params := url.Values{
		"param1": {"value1"},
		"param2": {"value2"},
	}

	signedURL, err := sg.GenerateSignature("/test", "GET", params)
	if err != nil {
		t.Fatalf("GenerateSignature failed: %v", err)
	}

	t.Logf("Signed URL: %s", signedURL)

	// 验证签名
	parsedURL, err := url.Parse(signedURL)
	if err != nil {
		t.Fatalf("Parse URL failed: %v", err)
	}

	if !util.VerifySignature("test-secret", "sign", "ts", "ak", parsedURL.Query(), "GET", "/test") {
		t.Error("Signature verification failed")
	}
}
