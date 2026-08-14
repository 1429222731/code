// Package output 负责资产结果的格式化渲染。
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/1429222731/code/internal/model"
)

// Render 以示例对齐的文本格式输出资产。
//
//	services:
//	5000/tcp qdiscover:
//	Name=slw-nas
//	IPv4=192.168.1.100
//	IPv6=fe80::265e:beff:fe69:a313
//	Hostname=slw-nas.local
//	TTL=120
//	accessType=https,accessPort=86,model=TS-X64,...
func Render(services []*model.Service, w io.Writer) error {
	sorted := append([]*model.Service(nil), services...)
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Instance < b.Instance
	})

	if _, err := fmt.Fprintln(w, "services:"); err != nil {
		return err
	}
	for _, s := range sorted {
		if err := renderService(s, w); err != nil {
			return err
		}
	}
	return nil
}

func renderService(s *model.Service, w io.Writer) error {
	if s.Port > 0 {
		if _, err := fmt.Fprintf(w, "%d/%s %s:\n", s.Port, s.Proto, s.Type); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(w, "%s:\n", s.Type); err != nil {
			return err
		}
	}
	lines := []string{"Name=" + s.Instance}
	for _, ip := range s.IPv4 {
		lines = append(lines, "IPv4="+ip)
	}
	for _, ip := range s.IPv6 {
		lines = append(lines, "IPv6="+ip)
	}
	if s.Hostname != "" {
		lines = append(lines, "Hostname="+s.Hostname)
	}
	if s.TTL > 0 {
		lines = append(lines, fmt.Sprintf("TTL=%d", s.TTL))
	}
	// 深度识别 banner：TXT 记录按逗号连接为一行。
	if len(s.TXT) > 0 {
		lines = append(lines, strings.Join(s.TXT, ","))
	}
	for _, ln := range lines {
		if _, err := fmt.Fprintln(w, ln); err != nil {
			return err
		}
	}
	return nil
}

// RenderJSON 以 JSON 数组输出资产。
func RenderJSON(services []*model.Service, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(services)
}
