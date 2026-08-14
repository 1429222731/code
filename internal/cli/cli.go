// Package cli 负责解析命令行参数并组装扫描配置。
package cli

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/1429222731/code/internal/portrange"
)

// Config 为一次扫描的完整配置。
type Config struct {
	CIDRs   []*net.IPNet
	Ports   portrange.PortRange
	Timeout time.Duration
	Workers int
	JSON    bool
	MaxIPs  int
}

// Parse 解析命令行参数为配置。
// cidrStr 支持逗号分隔的多个 CIDR，如 "192.168.1.0/24,10.0.0.0/16"。
func Parse(cidrStr, portStr string, timeout time.Duration, workers int, jsonOut bool, maxIPs int) (*Config, error) {
	cidrs, err := parseCIDRs(cidrStr)
	if err != nil {
		return nil, err
	}
	pr, err := portrange.Parse(portStr)
	if err != nil {
		return nil, fmt.Errorf("端口范围错误: %w", err)
	}
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	if workers <= 0 {
		workers = 200
	}
	if maxIPs <= 0 {
		maxIPs = 65536
	}
	return &Config{
		CIDRs:   cidrs,
		Ports:   pr,
		Timeout: timeout,
		Workers: workers,
		JSON:    jsonOut,
		MaxIPs:  maxIPs,
	}, nil
}

func parseCIDRs(s string) ([]*net.IPNet, error) {
	if strings.TrimSpace(s) == "" {
		return nil, fmt.Errorf("缺少 -cidr 参数（如 192.168.1.0/24）")
	}
	var out []*net.IPNet
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("CIDR %q 无效: %w", part, err)
		}
		out = append(out, ipnet)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("缺少有效的 CIDR")
	}
	return out, nil
}

// IPInCIDRs 判断 ip 是否落在任一 CIDR 内。
func IPInCIDRs(ip net.IP, cidrs []*net.IPNet) bool {
	for _, n := range cidrs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
