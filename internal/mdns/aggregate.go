package mdns

import (
	"net"
	"sort"
	"strings"

	"github.com/1429222731/code/internal/cli"
	"github.com/1429222731/code/internal/model"
	"github.com/1429222731/code/internal/parse"
	"github.com/1429222731/code/internal/portrange"
)

// Aggregate 将记录集合聚合为资产列表，并依次做 CIDR 过滤与端口过滤。
// 纯函数，便于单元测试；调用方需保证 rec 不再被并发写入。
func Aggregate(rec *parse.Records, cidrs []*net.IPNet, pr portrange.PortRange) []*model.Service {
	index := map[string]*model.Service{}
	var out []*model.Service
	for _, typeFQDN := range parse.ServiceTypes(rec) {
		typ, proto, ok := parse.TypeParts(typeFQDN)
		if !ok {
			continue
		}
		for _, instFQDN := range rec.PTR[typeFQDN] {
			inst := parse.InstanceName(instFQDN, typeFQDN)
			key := typeFQDN + "\x00" + instFQDN
			svc := index[key]
			if svc == nil {
				svc = &model.Service{Type: typ, Proto: proto, Instance: inst}
				index[key] = svc
				out = append(out, svc)
			}
			fillService(svc, instFQDN, rec)
		}
	}

	out = filterByCIDR(out, cidrs)
	out = filterByPorts(out, pr)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Instance < b.Instance
	})
	return out
}

// fillService 用 SRV/TXT/A/AAAA/SRC 记录补全单个服务。
func fillService(svc *model.Service, instFQDN string, rec *parse.Records) {
	if srv := rec.SRV[instFQDN]; srv != nil {
		svc.Port = int(srv.Port)
		host := lowerFQDN(srv.Target)
		if host != "" && host != "." {
			svc.Hostname = host
		}
		if ttl, ok := rec.SRVTTL[instFQDN]; ok {
			svc.TTL = ttl
		}
		// 目标主机名对应的 A/AAAA。
		svc.IPv4 = mergeIPStrings(svc.IPv4, ipStrings(rec.A[host]))
		svc.IPv6 = mergeIPStrings(svc.IPv6, ipStrings(rec.AAAA[host]))
	}
	// 源 IP 补全资产地址（A 记录缺失时仍能定位设备）。
	svc.IPv4 = mergeIPStrings(svc.IPv4, ipStrings(rec.SRC[instFQDN]))
	if len(rec.TXT[instFQDN]) > 0 {
		svc.TXT = rec.TXT[instFQDN]
	}
	if svc.TTL == 0 {
		if ttl, ok := rec.PTRTTL[instFQDN]; ok {
			svc.TTL = ttl
		}
	}
}

// filterByCIDR 丢弃已知 IPv4 均不在目标网段内的资产。
// 无任何 IPv4 信息的资产（如纯组播 PTR）视为本地可达，予以保留。
func filterByCIDR(svcs []*model.Service, cidrs []*net.IPNet) []*model.Service {
	out := svcs[:0]
	for _, s := range svcs {
		if len(s.IPv4) == 0 {
			out = append(out, s)
			continue
		}
		keep := false
		for _, ip := range s.IPv4 {
			if cli.IPInCIDRs(net.ParseIP(ip), cidrs) {
				keep = true
				break
			}
		}
		if keep {
			out = append(out, s)
		}
	}
	return out
}

// filterByPorts 按端口范围过滤；端口 0（未知）仅在范围为全端口时保留。
func filterByPorts(svcs []*model.Service, pr portrange.PortRange) []*model.Service {
	out := svcs[:0]
	for _, s := range svcs {
		if pr.Contains(s.Port) {
			out = append(out, s)
		}
	}
	return out
}

func lowerFQDN(s string) string {
	return strings.ToLower(strings.TrimSpace(trimDots(s)))
}

func trimDots(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '.' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}

func ipStrings(list []net.IP) []string {
	out := make([]string, 0, len(list))
	for _, ip := range list {
		out = append(out, ip.String())
	}
	return out
}

func mergeIPStrings(a, b []string) []string {
	for _, x := range b {
		dup := false
		for _, y := range a {
			if y == x {
				dup = true
				break
			}
		}
		if !dup {
			a = append(a, x)
		}
	}
	return a
}
