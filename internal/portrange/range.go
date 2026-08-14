// Package portrange 提供端口范围解析与判定。
package portrange

import (
	"fmt"
	"strconv"
	"strings"
)

// Range 表示一个闭区间 [Lo, Hi]。
type Range struct{ Lo, Hi int }

// PortRange 由若干闭区间组成；"all" 等价于覆盖全部端口。
type PortRange struct {
	ranges []Range
}

// All 返回覆盖全部端口（含 0，即"未知端口"）的范围。
func All() PortRange {
	return PortRange{ranges: []Range{{0, 65535}}}
}

// Parse 解析端口范围字符串，支持如下形式：
//
//	"all"          → 全部端口
//	"1-1000"       → 闭区间
//	"80,443"       → 逗号分隔的单端口
//	"1-5,800-900"  → 逗号分隔的多区间混合
func Parse(s string) (PortRange, error) {
	if strings.TrimSpace(s) == "" || strings.EqualFold(strings.TrimSpace(s), "all") {
		return All(), nil
	}
	pr := PortRange{}
	seen := map[Range]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.IndexByte(part, '-'); i >= 0 {
			loS, hiS := strings.TrimSpace(part[:i]), strings.TrimSpace(part[i+1:])
			lo, err := strconv.Atoi(loS)
			if err != nil {
				return PortRange{}, fmt.Errorf("无效端口 %q", part)
			}
			hi, err := strconv.Atoi(hiS)
			if err != nil {
				return PortRange{}, fmt.Errorf("无效端口 %q", part)
			}
			if lo < 0 || hi > 65535 || lo > hi {
				return PortRange{}, fmt.Errorf("端口区间无效 %q", part)
			}
			r := Range{lo, hi}
			if !seen[r] {
				seen[r] = true
				pr.ranges = append(pr.ranges, r)
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 0 || p > 65535 {
			return PortRange{}, fmt.Errorf("无效端口 %q", part)
		}
		r := Range{p, p}
		if !seen[r] {
			seen[r] = true
			pr.ranges = append(pr.ranges, r)
		}
	}
	if len(pr.ranges) == 0 {
		return PortRange{}, fmt.Errorf("空端口范围")
	}
	return pr, nil
}

// Contains 判断端口 port 是否在范围内。0 表示未知端口，仅 "all" 包含。
func (p PortRange) Contains(port int) bool {
	for _, r := range p.ranges {
		if port >= r.Lo && port <= r.Hi {
			return true
		}
	}
	return false
}

// String 返回可读的范围描述。
func (p PortRange) String() string {
	parts := make([]string, 0, len(p.ranges))
	for _, r := range p.ranges {
		if r.Lo == r.Hi {
			parts = append(parts, strconv.Itoa(r.Lo))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", r.Lo, r.Hi))
		}
	}
	return strings.Join(parts, ",")
}
