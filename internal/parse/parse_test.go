package parse

import (
	"net"
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

// qdiscoverMsg 构造一条模拟 QNAP NAS 对 _qdiscover._tcp.local PTR 查询的应答，
// 与 docs/README.md 示例中的 qdiscover 条目字段一一对应。
func qdiscoverMsg() *dns.Msg {
	m := new(dns.Msg)
	m.Response = true
	m.Answer = []dns.RR{
		&dns.PTR{
			Hdr: dns.RR_Header{Name: "_services._dns-sd._udp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 4500},
			Ptr: "_qdiscover._tcp.local.",
		},
		&dns.PTR{
			Hdr: dns.RR_Header{Name: "_qdiscover._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 4500},
			Ptr: "slw-nas._qdiscover._tcp.local.",
		},
		&dns.SRV{
			Hdr:      dns.RR_Header{Name: "slw-nas._qdiscover._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 120},
			Priority: 0, Weight: 0, Port: 5000, Target: "slw-nas.local.",
		},
		&dns.TXT{
			Hdr: dns.RR_Header{Name: "slw-nas._qdiscover._tcp.local.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 4500},
			Txt: []string{"accessType=https", "accessPort=86", "model=TS-X64", "displayModel=TS-464C", "fwVer=5.2.9", "fwBuildNum=20260214"},
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "slw-nas.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
			A:   net.ParseIP("192.168.1.100"),
		},
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "slw-nas.local.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 120},
			AAAA: net.ParseIP("fe80::265e:beff:fe69:a313"),
		},
	}
	return m
}

func TestAddMsgExtractsQNAPRecords(t *testing.T) {
	rec := NewRecords()
	AddMsg(qdiscoverMsg(), net.ParseIP("192.168.1.100"), rec)

	types := ServiceTypes(rec)
	if want := []string{"_qdiscover._tcp.local."}; !reflect.DeepEqual(types, want) {
		t.Errorf("ServiceTypes = %v, want %v", types, want)
	}

	typ, proto, ok := TypeParts("_qdiscover._tcp.local.")
	if !ok || typ != "qdiscover" || proto != "tcp" {
		t.Errorf("TypeParts = (%q,%q,%v), want (qdiscover,tcp,true)", typ, proto, ok)
	}

	insts := rec.PTR["_qdiscover._tcp.local."]
	if want := []string{"slw-nas._qdiscover._tcp.local."}; !reflect.DeepEqual(insts, want) {
		t.Errorf("PTR instances = %v, want %v", insts, want)
	}

	if got := InstanceName("slw-nas._qdiscover._tcp.local.", "_qdiscover._tcp.local."); got != "slw-nas" {
		t.Errorf("InstanceName = %q, want slw-nas", got)
	}

	srv := rec.SRV["slw-nas._qdiscover._tcp.local."]
	if srv == nil || srv.Port != 5000 || srv.Target != "slw-nas.local." {
		t.Errorf("SRV = %+v, want port=5000 target=slw-nas.local.", srv)
	}

	txt := rec.TXT["slw-nas._qdiscover._tcp.local."]
	wantTXT := []string{"accessType=https", "accessPort=86", "model=TS-X64", "displayModel=TS-464C", "fwVer=5.2.9", "fwBuildNum=20260214"}
	if !reflect.DeepEqual(txt, wantTXT) {
		t.Errorf("TXT = %v, want %v", txt, wantTXT)
	}

	if len(rec.A["slw-nas.local."]) != 1 || rec.A["slw-nas.local."][0].String() != "192.168.1.100" {
		t.Errorf("A = %v, want [192.168.1.100]", rec.A["slw-nas.local."])
	}
	if len(rec.AAAA["slw-nas.local."]) != 1 || rec.AAAA["slw-nas.local."][0].String() != "fe80::265e:beff:fe69:a313" {
		t.Errorf("AAAA = %v, want [fe80::265e:beff:fe69:a313]", rec.AAAA["slw-nas.local."])
	}
}

func TestAddMsgKeepsTXTStringsSeparate(t *testing.T) {
	m := new(dns.Msg)
	m.Response = true
	m.Answer = []dns.RR{
		&dns.TXT{
			Hdr: dns.RR_Header{Name: "a._x._tcp.local.", Rrtype: dns.TypeTXT, Class: dns.ClassINET},
			Txt: []string{"path=/", "uuid=abc"},
		},
	}
	rec := NewRecords()
	AddMsg(m, nil, rec)
	got := rec.TXT["a._x._tcp.local."]
	if want := []string{"path=/", "uuid=abc"}; !reflect.DeepEqual(got, want) {
		t.Errorf("TXT = %v, want %v", got, want)
	}
}
