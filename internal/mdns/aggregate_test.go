package mdns

import (
	"net"
	"reflect"
	"testing"

	"github.com/miekg/dns"

	"github.com/1429222731/code/internal/parse"
	"github.com/1429222731/code/internal/portrange"
)

// svcMsg 构造一条 mDNS 应答：_services 枚举 + 某服务类型的实例（含 SRV/TXT/A/AAAA）。
func svcMsg(typ, proto, instance, host string, port int, txts []string, ip4, ip6 string) *dns.Msg {
	typeFQDN := "_" + typ + "._" + proto + ".local."
	instFQDN := instance + "." + typeFQDN
	hostFQDN := host + ".local."
	m := new(dns.Msg)
	m.Response = true
	m.Answer = []dns.RR{
		&dns.PTR{
			Hdr: dns.RR_Header{Name: parse.ServicesName, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 4500},
			Ptr: typeFQDN,
		},
		&dns.PTR{
			Hdr: dns.RR_Header{Name: typeFQDN, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 4500},
			Ptr: instFQDN,
		},
		&dns.SRV{
			Hdr:      dns.RR_Header{Name: instFQDN, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 120},
			Priority: 0, Weight: 0, Port: uint16(port), Target: hostFQDN,
		},
		&dns.TXT{
			Hdr: dns.RR_Header{Name: instFQDN, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 4500},
			Txt: txts,
		},
	}
	if ip4 != "" {
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: hostFQDN, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
			A:   net.ParseIP(ip4),
		})
	}
	if ip6 != "" {
		m.Answer = append(m.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: hostFQDN, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 120},
			AAAA: net.ParseIP(ip6),
		})
	}
	return m
}

func TestAggregateQNAPExample(t *testing.T) {
	rec := parse.NewRecords()
	parse.AddMsg(svcMsg("qdiscover", "tcp", "slw-nas", "slw-nas", 5000,
		[]string{"accessType=https", "accessPort=86", "model=TS-X64", "displayModel=TS-464C", "fwVer=5.2.9", "fwBuildNum=20260214"},
		"192.168.1.100", "fe80::265e:beff:fe69:a313"), net.ParseIP("192.168.1.100"), rec)
	parse.AddMsg(svcMsg("smb", "tcp", "slw-nas", "slw-nas", 445,
		nil, "192.168.1.100", ""), net.ParseIP("192.168.1.100"), rec)

	_, cidr, _ := net.ParseCIDR("192.168.1.0/24")
	svcs := Aggregate(rec, []*net.IPNet{cidr}, portrange.All())

	if len(svcs) != 2 {
		t.Fatalf("Aggregate returned %d services, want 2: %+v", len(svcs), svcs)
	}

	// 排序：qdiscover 在前（q < s）。
	qd := svcs[0]
	if qd.Type != "qdiscover" || qd.Proto != "tcp" || qd.Instance != "slw-nas" || qd.Port != 5000 ||
		qd.Hostname != "slw-nas.local" || qd.TTL != 120 {
		t.Errorf("qdiscover 字段不符: %+v", qd)
	}
	if want := []string{"192.168.1.100"}; !reflect.DeepEqual(qd.IPv4, want) {
		t.Errorf("qdiscover IPv4 = %v, want %v", qd.IPv4, want)
	}
	if want := []string{"fe80::265e:beff:fe69:a313"}; !reflect.DeepEqual(qd.IPv6, want) {
		t.Errorf("qdiscover IPv6 = %v, want %v", qd.IPv6, want)
	}
	wantTXT := []string{"accessType=https", "accessPort=86", "model=TS-X64", "displayModel=TS-464C", "fwVer=5.2.9", "fwBuildNum=20260214"}
	if !reflect.DeepEqual(qd.TXT, wantTXT) {
		t.Errorf("qdiscover TXT = %v, want %v", qd.TXT, wantTXT)
	}
}

func TestAggregateCIDRAndPortFilter(t *testing.T) {
	rec := parse.NewRecords()
	// 网段内：http on 5000。
	parse.AddMsg(svcMsg("http", "tcp", "nas-a", "nas-a", 5000, []string{"path=/"}, "192.168.1.10", ""), net.ParseIP("192.168.1.10"), rec)
	// 网段内：smb on 445。
	parse.AddMsg(svcMsg("smb", "tcp", "nas-a", "nas-a", 445, nil, "192.168.1.10", ""), net.ParseIP("192.168.1.10"), rec)
	// 网段外：ssh on 22。
	parse.AddMsg(svcMsg("ssh", "tcp", "other", "other", 22, nil, "10.0.0.9", ""), net.ParseIP("10.0.0.9"), rec)
	// 未知端口：device-info（仅有 PTR 无 SRV 的场景以 0 端口表达）。
	rec.TXT["n._device-info._tcp.local."] = []string{"model=Xserve"}
	rec.PTR["_device-info._tcp.local."] = []string{"n._device-info._tcp.local."}
	rec.Types["_device-info._tcp.local."] = struct{}{}

	_, cidr, _ := net.ParseCIDR("192.168.1.0/24")
	pr, _ := portrange.Parse("80-6000")

	svcs := Aggregate(rec, []*net.IPNet{cidr}, pr)
	// 期望：http(5000) 命中；smb(445) 命中；ssh(10.0.0.9) 因不在网段被剔除；device-info(端口未知 0) 因非全端口被剔除。
	if len(svcs) != 2 {
		t.Fatalf("Aggregate returned %d services, want 2: %+v", len(svcs), svcs)
	}
	types := map[string]bool{}
	for _, s := range svcs {
		types[s.Type] = true
	}
	if !types["http"] || !types["smb"] {
		t.Errorf("聚合结果类型不符: %+v", svcs)
	}

	// 全端口范围时，未知端口条目应保留。
	all := Aggregate(rec, []*net.IPNet{cidr}, portrange.All())
	found := false
	for _, s := range all {
		if s.Type == "device-info" {
			found = true
			if s.Port != 0 {
				t.Errorf("device-info Port = %d, want 0", s.Port)
			}
		}
	}
	if !found {
		t.Errorf("全端口范围下未保留未知端口条目: %+v", all)
	}
}
