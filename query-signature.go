package cqs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(QuerySignature{})
	httpcaddyfile.RegisterHandlerDirective("query_signature", parseCaddyfile)
}

// QuerySignature 实现query参数签名校验
type QuerySignature struct {
	// 需要校验的路径前缀
	PathPrefixes []string `json:"path_prefixes,omitempty"`

	// 需要排除的路径
	ExcludePaths []string `json:"exclude_paths,omitempty"`

	// 签名密钥
	SecretKey string `json:"secret_key"`

	// 签名参数名，默认为 "sign"
	SignParam string `json:"sign_param,omitempty"`

	// 时间戳参数名，默认为 "timestamp"
	TimestampParam string `json:"timestamp_param,omitempty"`

	// 签名有效期（秒），0表示不检查
	ExpireSeconds int64 `json:"expire_seconds,omitempty"`

	// 需要参与签名的排除参数
	ExcludeParams []string `json:"exclude_params,omitempty"`

	logger *zap.Logger
}

// CaddyModule 返回Caddy模块信息
func (QuerySignature) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.query_signature",
		New: func() caddy.Module { return new(QuerySignature) },
	}
}

// Provision 初始化模块
func (m *QuerySignature) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)

	// 设置默认值
	if m.SignParam == "" {
		m.SignParam = "sign"
	}
	if m.TimestampParam == "" {
		m.TimestampParam = "timestamp"
	}

	if m.SecretKey == "" {
		return fmt.Errorf("secret_key is required")
	}

	return nil
}

// Validate 验证配置
func (m *QuerySignature) Validate() error {
	if m.SecretKey == "" {
		return fmt.Errorf("secret_key must be set")
	}
	return nil
}

// ServeHTTP 处理HTTP请求
func (m QuerySignature) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// 检查是否需要签名校验
	if !m.needCheck(r.URL.Path) {
		return next.ServeHTTP(w, r)
	}

	// 验证签名
	if err := m.verifySignature(r); err != nil {
		m.logger.Warn("signature verification failed",
			zap.String("path", r.URL.Path),
			zap.Error(err),
			zap.String("client_ip", r.RemoteAddr))

		return caddyhttp.Error(http.StatusUnauthorized, err)
	}

	m.logger.Debug("signature verification passed",
		zap.String("path", r.URL.Path),
		zap.String("client_ip", r.RemoteAddr))

	return next.ServeHTTP(w, r)
}

// needCheck 检查路径是否需要签名校验
func (m *QuerySignature) needCheck(path string) bool {
	// 检查排除路径
	for _, exclude := range m.ExcludePaths {
		if strings.HasPrefix(path, exclude) {
			return false
		}
	}

	// 如果没有指定路径前缀，校验所有请求
	if len(m.PathPrefixes) == 0 {
		return true
	}

	// 检查是否在需要校验的路径中
	for _, prefix := range m.PathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	return false
}

// verifySignature 验证签名
func (m *QuerySignature) verifySignature(r *http.Request) error {
	query := r.URL.Query()

	// 检查时间戳
	if m.ExpireSeconds > 0 {
		timestampStr := query.Get(m.TimestampParam)
		if timestampStr == "" {
			return fmt.Errorf("timestamp parameter '%s' is required", m.TimestampParam)
		}

		timestamp, err := time.Parse(time.RFC3339, timestampStr)
		if err != nil {
			// 尝试解析为Unix时间戳
			timestampInt, err := strconv.ParseInt(timestampStr, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid timestamp format")
			}
			timestamp = time.Unix(timestampInt, 0)
		}

		// 检查时间戳是否过期
		if time.Since(timestamp).Seconds() > float64(m.ExpireSeconds) {
			return fmt.Errorf("request expired")
		}
	}

	// 获取签名
	sign := query.Get(m.SignParam)
	if sign == "" {
		return fmt.Errorf("signature parameter '%s' is required", m.SignParam)
	}

	// 移除签名参数进行验证
	query.Del(m.SignParam)

	// 生成待签名字符串
	stringToSign := m.buildStringToSign(query, r)

	// 计算HMAC-SHA256签名
	expectedSign := m.calculateSignature(stringToSign)

	// m.logger.Debug("verifySignature",
	// 	zap.String("stringToSign", stringToSign),
	// 	zap.String("expectedSign", expectedSign),
	// 	zap.String("sign", sign))

	// 比较签名
	if !hmac.Equal([]byte(sign), []byte(expectedSign)) {
		return fmt.Errorf("invalid signature, expected: %s, got: %s, stringToSign: %s",
			expectedSign, sign, stringToSign)
	}

	return nil
}

// buildStringToSign 构建待签名字符串
func (m *QuerySignature) buildStringToSign(query url.Values, r *http.Request) string {
	// 按参数名排序
	var keys []string
	for k := range query {
		// 排除不需要参与签名的参数
		if !m.isExcludedParam(k) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	// 构建参数字符串
	var params []string
	for _, k := range keys {
		values := query[k]
		sort.Strings(values)
		for _, v := range values {
			params = append(params, fmt.Sprintf("%s=%s", k, v))
		}
	}

	// 添加请求路径和方法（可选增强）
	path := r.URL.Path
	// if r.URL.RawQuery != "" {
	// 	path = fmt.Sprintf("%s?%s", r.URL.Path, r.URL.RawQuery)
	// }

	return fmt.Sprintf("%s&%s&%s", r.Method, path, strings.Join(params, "&"))
}

// calculateSignature 计算签名
func (m *QuerySignature) calculateSignature(data string) string {
	h := hmac.New(sha256.New, []byte(m.SecretKey))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// isExcludedParam 检查参数是否排除
func (m *QuerySignature) isExcludedParam(param string) bool {
	for _, exclude := range m.ExcludeParams {
		if param == exclude {
			return true
		}
	}
	return false
}

// UnmarshalCaddyfile 解析Caddyfile配置
func (m *QuerySignature) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		// 解析参数
		for d.NextBlock(0) {
			switch d.Val() {
			case "path":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.PathPrefixes = append(m.PathPrefixes, d.Val())

			case "exclude":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.ExcludePaths = append(m.ExcludePaths, d.Val())

			case "secret_key":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.SecretKey = d.Val()

			case "sign_param":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.SignParam = d.Val()

			case "timestamp_param":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.TimestampParam = d.Val()

			case "expire_seconds":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var err error
				m.ExpireSeconds, err = strconv.ParseInt(d.Val(), 10, 64)
				if err != nil {
					return d.Errf("invalid expire_seconds: %v", err)
				}

			case "exclude_param":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.ExcludeParams = append(m.ExcludeParams, d.Val())

			default:
				return d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}

	return nil
}

// parseCaddyfile 解析Caddyfile
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var qs QuerySignature
	err := qs.UnmarshalCaddyfile(h.Dispenser)
	return qs, err
}
