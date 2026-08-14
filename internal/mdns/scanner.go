// Package mdns 实现 mDNS/DNS-SD 发现引擎：组播枚举 + 单播探测 + 聚合过滤。
package mdns

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/1429222731/code/internal/model"
	"github.com/1429222731/code/internal/parse"
	"github.com/1429222731/code/internal/portrange"
)

const (
	multicastAddr4 = "224.0.0.251"
	mdnsPort       = 5353
	// quBit 为问题 class 中请求单播应答的位（RFC 6762）。
	quBit = 0x8000
)

// commonTypes 为常见服务类型，在 _services 枚举之外额外探测，提升覆盖率。
var commonTypes = []string{
	"_workstation._tcp.local.",
	"_http._tcp.local.",
	"_smb._tcp.local.",
	"_afpovertcp._tcp.local.",
	"_device-info._tcp.local.",
	"_qdiscover._tcp.local.",
	"_https._tcp.local.",
	"_ssh._tcp.local.",
	"_ftp._tcp.local.",
	"_ipp._tcp.local.",
	"_printer._tcp.local.",
	"_airplay._tcp.local.",
	"_raop._tcp.local.",
	"_googlecast._tcp.local.",
	"_hap._tcp.local.",
	"_companion-link._tcp.local.",
	"_webdav._tcp.local.",
	"_webdavs._tcp.local.",
	"_sftp-ssh._tcp.local.",
}

// Config 为扫描引擎配置。
type Config struct {
	CIDRs   []*net.IPNet
	Ports   portrange.PortRange
	Timeout time.Duration
	Workers int
	MaxIPs  int
	// Debug 为 true 时收集接收统计（供排障）。
	Debug bool
}

// Stats 为一次扫描的接收统计。
type Stats struct {
	Packets   int64
	Responses int64
	Queries   int64
	Types     int
}

// Scanner 持有一个组播 UDP socket，负责收发 mDNS 报文。
type Scanner struct {
	cfg      Config
	conn     *net.UDPConn
	mcastDst *net.UDPAddr
	rec      *parse.Records
	mu       sync.Mutex
	readDone chan struct{}
	deadline time.Time
	ctx      context.Context
	stats    Stats
}

// New 创建并初始化 Scanner，加入组播组 224.0.0.251:5353。
func New(cfg Config) (*Scanner, error) {
	if cfg.Workers <= 0 {
		cfg.Workers = 200
	}
	if cfg.MaxIPs <= 0 {
		cfg.MaxIPs = 65536
	}
	addr := &net.UDPAddr{IP: net.ParseIP(multicastAddr4), Port: mdnsPort}
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("加入组播组失败（可能是防火墙拦截 5353/UDP）: %w", err)
	}
	_ = conn.SetReadBuffer(1 << 20)
	return &Scanner{
		cfg:      cfg,
		conn:     conn,
		mcastDst: &net.UDPAddr{IP: net.ParseIP(multicastAddr4), Port: mdnsPort},
		rec:      parse.NewRecords(),
		readDone: make(chan struct{}),
	}, nil
}

// Run 执行完整扫描流程，返回端口过滤后的资产列表。
func (s *Scanner) Run(ctx context.Context) ([]*model.Service, error) {
	s.ctx = ctx
	s.deadline = time.Now().Add(s.cfg.Timeout)

	go s.readLoop()

	// 阶段 A：组播枚举服务类型。
	s.sendQuery(s.mcastDst, parse.ServicesName, dns.TypePTR, false)
	s.wait(2 * time.Second)
	types := s.typesSnapshot()

	// 阶段 B：组播查询各服务类型的实例（PTR，应答自带 SRV/TXT/A/AAAA）。
	allTypes := mergeTypes(types, commonTypes)
	for _, t := range allTypes {
		s.sendQuery(s.mcastDst, t, dns.TypePTR, false)
	}
	s.wait(3 * time.Second)

	// 阶段 C：对 CIDR 内每个 IP 单播探测（让"IP 网段"输入真正生效）。
	s.unicastProbe(allTypes)
	s.wait(3 * time.Second)

	// 阶段 D：对缺 SRV 的实例补发解析查询。
	s.resolveMissing()
	s.wait(2 * time.Second)

	// 兜底：跑满整个时间窗口。
	if !s.deadline.IsZero() {
		if d := time.Until(s.deadline); d > 0 {
			s.wait(d)
		}
	}

	// 停止接收，等待 readLoop 退出后聚合，避免数据竞争。
	_ = s.conn.Close()
	<-s.readDone

	return Aggregate(s.rec, s.cfg.CIDRs, s.cfg.Ports), nil
}

// readLoop 持续读取 socket，解析应答报文并入记录集合。
func (s *Scanner) readLoop() {
	defer close(s.readDone)
	buf := make([]byte, 65535)
	for {
		n, src, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		s.mu.Lock()
		s.stats.Packets++
		m := new(dns.Msg)
		if err := m.Unpack(buf[:n]); err != nil {
			s.mu.Unlock()
			continue
		}
		if !m.Response {
			s.mu.Unlock()
			continue
		}
		s.stats.Responses++
		parse.AddMsg(m, src.IP, s.rec)
		s.mu.Unlock()
	}
}

// sendQuery 发送一条 mDNS 查询。qu 为 true 时请求单播应答。
func (s *Scanner) sendQuery(dst *net.UDPAddr, name string, qtype uint16, qu bool) {
	m := new(dns.Msg)
	m.Id = 0
	m.Question = []dns.Question{{
		Name:   dns.Fqdn(name),
		Qtype:  qtype,
		Qclass: uint16(dns.ClassINET),
	}}
	if qu {
		m.Question[0].Qclass |= quBit
	}
	b, err := m.Pack()
	if err != nil {
		return
	}
	s.mu.Lock()
	s.stats.Queries++
	s.mu.Unlock()
	_, _ = s.conn.WriteToUDP(b, dst)
}

// Stats 返回扫描接收统计。
func (s *Scanner) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.Types = len(parse.ServiceTypes(s.rec))
	return s.stats
}

// wait 在时间窗口内等待（不超过总 deadline）。
func (s *Scanner) wait(d time.Duration) {
	if s.deadline.IsZero() {
		select {
		case <-time.After(d):
		case <-s.ctx.Done():
		}
		return
	}
	until := time.Until(s.deadline)
	if until <= 0 {
		return
	}
	if until < d {
		d = until
	}
	select {
	case <-time.After(d):
	case <-s.ctx.Done():
	}
}

// typesSnapshot 返回当前已发现的服务类型。
func (s *Scanner) typesSnapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return parse.ServiceTypes(s.rec)
}

// unicastProbe 对 CIDR 内每个 IP 单播查询 _services 与已知服务类型。
func (s *Scanner) unicastProbe(types []string) {
	ips := expandCIDRs(s.cfg.CIDRs, s.cfg.MaxIPs)
	if len(ips) == 0 {
		return
	}
	// 第一轮：单播枚举服务类型。
	s.runWorkers(ips, func(ip net.IP) {
		s.sendQuery(&net.UDPAddr{IP: ip, Port: mdnsPort}, parse.ServicesName, dns.TypePTR, true)
	})
	s.wait(2 * time.Second)

	// 合并单播新发现的类型，第二轮：单播查询各类型实例。
	all := mergeTypes(types, s.typesSnapshot())
	s.runWorkers(ips, func(ip net.IP) {
		for _, t := range all {
			s.sendQuery(&net.UDPAddr{IP: ip, Port: mdnsPort}, t, dns.TypePTR, true)
		}
	})
	s.wait(2 * time.Second)
}

// resolveMissing 对缺少 SRV 的实例补发解析查询。
func (s *Scanner) resolveMissing() {
	s.mu.Lock()
	var missing []string
	for owner, srv := range s.rec.SRV {
		if srv == nil {
			missing = append(missing, owner)
		}
	}
	for owner := range s.rec.PTR {
		if _, ok := s.rec.SRV[owner]; !ok {
			missing = append(missing, owner)
		}
	}
	s.mu.Unlock()
	sort.Strings(missing)
	for _, inst := range missing {
		s.sendQuery(s.mcastDst, inst, dns.TypeSRV, false)
		s.sendQuery(s.mcastDst, inst, dns.TypeTXT, false)
		s.sendQuery(s.mcastDst, inst, dns.TypeANY, false)
	}
}

// runWorkers 以工作池并发执行 fn。
func (s *Scanner) runWorkers(items []net.IP, fn func(net.IP)) {
	if len(items) == 0 {
		return
	}
	sem := make(chan struct{}, s.cfg.Workers)
	var wg sync.WaitGroup
	for _, ip := range items {
		if s.ctx != nil && s.ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(ip)
		}(ip)
	}
	wg.Wait()
}

func mergeTypes(a, b []string) []string {
	set := map[string]struct{}{}
	for _, t := range a {
		set[t] = struct{}{}
	}
	for _, t := range b {
		set[t] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// expandCIDRs 展开 CIDR 为 IP 列表（去重），受 limit 上限保护。
func expandCIDRs(cidrs []*net.IPNet, limit int) []net.IP {
	seen := map[[4]byte]struct{}{}
	var ips []net.IP
	for _, n := range cidrs {
		ip4 := n.IP.To4()
		if ip4 == nil {
			continue
		}
		ones, bits := n.Mask.Size()
		hostBits := bits - ones
		if hostBits < 0 || hostBits > 32 {
			continue
		}
		var total uint64 = 1 << hostBits
		count := total
		if count > uint64(limit) {
			count = uint64(limit)
		}
		start := binary.BigEndian.Uint32(ip4) & ^((uint32(1) << hostBits) - 1)
		for i := uint64(0); i < count; i++ {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], start+uint32(i))
			if _, ok := seen[b]; ok {
				continue
			}
			seen[b] = struct{}{}
			ips = append(ips, net.IPv4(b[0], b[1], b[2], b[3]))
		}
	}
	return ips
}
