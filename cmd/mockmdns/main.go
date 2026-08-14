// mockmdns 是本地的 mDNS 应答模拟器：向组播组周期广播 docs/README.md 示例中
// 那台 QNAP NAS 的 6 条服务，用于在没有真实 mDNS 设备的环境下联调/演示扫描器。
//
// 用法：先启动本程序，再运行 mdnsmap 扫描，即可看到示例格式的资产输出。
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/miekg/dns"
)

func main() {
	var (
		ifaceIP = flag.String("ip", "192.168.0.200", "模拟设备的 IPv4 地址（需落在被扫描网段内）")
		period  = flag.Duration("period", 2*time.Second, "广播间隔")
	)
	flag.Parse()

	conn, err := net.ListenMulticastUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353})
	if err != nil {
		log.Fatalf("加入组播组失败: %v", err)
	}
	defer conn.Close()

	msg := exampleResponse(*ifaceIP)
	raw, err := msg.Pack()
	if err != nil {
		log.Fatalf("打包应答失败: %v", err)
	}

	dst := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
	log.Printf("mockmdns 启动：广播 %d 字节的示例应答（IP=%s，间隔 %s），Ctrl+C 退出",
		len(raw), *ifaceIP, *period)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	for {
		if _, err := conn.WriteToUDP(raw, dst); err != nil {
			log.Printf("广播失败: %v", err)
		}
		select {
		case <-time.After(*period):
		case <-stop:
			log.Println("退出")
			return
		}
	}
}

// exampleResponse 构造 docs/README.md 示例中 QNAP NAS 的完整 mDNS 应答。
func exampleResponse(ip4 string) *dns.Msg {
	m := new(dns.Msg)
	m.Response = true
	m.Authoritative = true
	const (
		host = "slw-nas.local."
		ip6  = "fe80::265e:beff:fe69:a313"
	)
	add := func(rrs ...dns.RR) { m.Answer = append(m.Answer, rrs...) }

	// _services 枚举。
	svcTypes := []string{"_workstation._tcp.local.", "_http._tcp.local.", "_smb._tcp.local.",
		"_qdiscover._tcp.local.", "_device-info._tcp.local.", "_afpovertcp._tcp.local."}
	for _, t := range svcTypes {
		add(&dns.PTR{Hdr: dns.RR_Header{Name: "_services._dns-sd._udp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 4500}, Ptr: t})
	}

	svcs := []struct {
		typ, proto, instance string
		port                 uint16
		txt                  []string
	}{
		{"workstation", "tcp", "slw-nas [24:5e:be:69:a3:13]", 9, nil},
		{"http", "tcp", "slw-nas", 5000, []string{"path=/"}},
		{"smb", "tcp", "slw-nas", 445, nil},
		{"qdiscover", "tcp", "slw-nas", 5000, []string{
			"accessType=https", "accessPort=86", "model=TS-X64",
			"displayModel=TS-464C", "fwVer=5.2.9", "fwBuildNum=20260214"}},
		{"device-info", "tcp", "slw-nas(AFP)", 548, []string{"model=Xserve"}},
		{"afpovertcp", "tcp", "slw-nas(AFP)", 548, nil},
	}
	for _, s := range svcs {
		typeFQDN := "_" + s.typ + "._" + s.proto + ".local."
		instFQDN := s.instance + "." + typeFQDN
		add(&dns.PTR{Hdr: dns.RR_Header{Name: typeFQDN, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 4500}, Ptr: instFQDN})
		add(&dns.SRV{Hdr: dns.RR_Header{Name: instFQDN, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 120}, Priority: 0, Weight: 0, Port: s.port, Target: host})
		if s.txt != nil {
			add(&dns.TXT{Hdr: dns.RR_Header{Name: instFQDN, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 4500}, Txt: s.txt})
		}
	}
	add(&dns.A{Hdr: dns.RR_Header{Name: host, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.ParseIP(ip4)})
	add(&dns.AAAA{Hdr: dns.RR_Header{Name: host, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 120}, AAAA: net.ParseIP(ip6)})
	return m
}
