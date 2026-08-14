// Package parse 将 mDNS/DNS-SD 报文解析为可聚合的记录集合。
package parse

import (
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

const (
	// ServicesName 为服务类型枚举的专用名称。
	ServicesName = "_services._dns-sd._udp.local."
)

// serviceTypeRe 匹配服务类型 FQDN，如 "_http._tcp.local."。
var serviceTypeRe = regexp.MustCompile(`^_([^.]+)\._(tcp|udp)\.local\.?$`)

// Records 聚合整个扫描窗口内从报文中抽取的全部记录。
type Records struct {
	// Types 为发现的服务类型 FQDN 集合，如 "_http._tcp.local."。
	Types map[string]struct{}
	// PTR 为 owner(服务类型 FQDN) -> 实例 FQDN 列表，如 "_http._tcp.local." -> "slw-nas._http._tcp.local."。
	PTR map[string][]string
	// SRV 为 owner(实例 FQDN) -> SRV 记录。
	SRV map[string]*dns.SRV
	// TXT 为 owner(实例 FQDN) -> TXT 字符串列表。
	TXT map[string][]string
	// A / AAAA 为主机名 -> 地址列表。
	A   map[string][]net.IP
	AAAA map[string][]net.IP
	// SRVTTL / PTRTTL 为对应记录的最低观察 TTL。
	SRVTTL map[string]uint32
	PTRTTL map[string]uint32
	// SRC 为 owner -> 声明该记录的源 IP（用于补全资产 IP）。
	SRC map[string][]net.IP
}

// NewRecords 返回一个空的记录集合。
func NewRecords() *Records {
	return &Records{
		Types:   map[string]struct{}{},
		PTR:     map[string][]string{},
		SRV:     map[string]*dns.SRV{},
		TXT:     map[string][]string{},
		A:       map[string][]net.IP{},
		AAAA:    map[string][]net.IP{},
		SRVTTL:  map[string]uint32{},
		PTRTTL:  map[string]uint32{},
		SRC:     map[string][]net.IP{},
	}
}

// AddMsg 将一条 DNS 报文中的记录并入 r。
func AddMsg(m *dns.Msg, src net.IP, r *Records) {
	if m == nil || r == nil {
		return
	}
	sections := [][]dns.RR{m.Answer, m.Ns, m.Extra}
	for _, sec := range sections {
		for _, rr := range sec {
			owner := lowerName(rr.Header().Name)
			r.SRC[owner] = appendIP(r.SRC[owner], src)
			switch v := rr.(type) {
			case *dns.PTR:
				target := lowerName(v.Ptr)
				if owner == ServicesName {
					// _services._dns-sd._udp.local -> 服务类型
					if IsServiceTypeName(target) {
						r.Types[target] = struct{}{}
					}
				} else if IsServiceTypeName(owner) {
					// 服务类型 -> 实例
					r.PTR[owner] = appendUnique(r.PTR[owner], target)
					if ttl, ok := r.PTRTTL[owner]; !ok || v.Hdr.Ttl < ttl {
						r.PTRTTL[owner] = v.Hdr.Ttl
					}
				}
			case *dns.SRV:
				r.SRV[owner] = v
				if ttl, ok := r.SRVTTL[owner]; !ok || v.Hdr.Ttl < ttl {
					r.SRVTTL[owner] = v.Hdr.Ttl
				}
			case *dns.TXT:
				// DNS-SD 中同一 TXT 记录里的每个字符串是一条独立的 key=value 属性，
				// 逐条保留；输出端再按逗号连接为一行。
				for _, s := range v.Txt {
					r.TXT[owner] = appendUnique(r.TXT[owner], s)
				}
			case *dns.A:
				if ip := v.A.To4(); ip != nil {
					r.A[owner] = appendIP(r.A[owner], ip)
				}
			case *dns.AAAA:
				if ip := v.AAAA.To16(); ip != nil {
					r.AAAA[owner] = appendIP(r.AAAA[owner], ip)
				}
			}
		}
	}
}

// ServiceTypes 返回所有发现的服务类型 FQDN（已排序、去重）。
// 来源包括 _services 枚举应答，以及报文里带实例 PTR 的服务类型。
func ServiceTypes(r *Records) []string {
	set := map[string]struct{}{}
	for t := range r.Types {
		set[t] = struct{}{}
	}
	for owner := range r.PTR {
		if IsServiceTypeName(owner) {
			set[owner] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// IsServiceTypeName 判断 name 是否为服务类型 FQDN（如 "_http._tcp.local."）。
func IsServiceTypeName(name string) bool {
	return serviceTypeRe.MatchString(name)
}

// TypeParts 从服务类型 FQDN 解析出类型名与协议，如 ("http","tcp")。
func TypeParts(typeFQDN string) (typ, proto string, ok bool) {
	m := serviceTypeRe.FindStringSubmatch(typeFQDN)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// InstanceName 从实例 FQDN 中剥离服务类型后缀得到实例名，
// 如 "slw-nas._http._tcp.local." + "_http._tcp.local." -> "slw-nas"。
func InstanceName(instFQDN, typeFQDN string) string {
	s := strings.TrimSuffix(instFQDN, typeFQDN)
	return strings.TrimSuffix(s, ".")
}

// lowerName 将 FQDN 转小写并确保结尾有 "."。
func lowerName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func appendIP(list []net.IP, ip net.IP) []net.IP {
	for _, x := range list {
		if x.Equal(ip) {
			return list
		}
	}
	return append(list, ip)
}
