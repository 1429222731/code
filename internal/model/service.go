// Package model 定义 mDNS 资产的数据模型。
package model

// Service 表示一条 mDNS/DNS-SD 资产：某个 IP 上暴露的一个服务实例。
type Service struct {
	// Type 为服务类型名（去掉下划线和后缀），如 "http"、"qdiscover"、"smb"。
	Type string `json:"type"`
	// Proto 为传输协议，如 "tcp"、"udp"。
	Proto string `json:"proto"`
	// Instance 为服务实例名，直接回显，可能包含厂商附加信息，如 "slw-nas [24:5e:be:69:a3:13]"。
	Instance string `json:"name"`
	// Hostname 为 SRV 记录目标主机名，如 "slw-nas.local"。
	Hostname string `json:"hostname,omitempty"`
	// Port 为 SRV 记录端口；0 表示未解析到（如仅有 PTR 记录）。
	Port int `json:"port"`
	// IPv4 为该资产关联的 IPv4 地址（去重）。
	IPv4 []string `json:"ipv4,omitempty"`
	// IPv6 为该资产关联的 IPv6 地址（去重）。
	IPv6 []string `json:"ipv6,omitempty"`
	// TXT 为 DNS-SD TXT 记录原文（每条一个 key=value 字符串）。
	TXT []string `json:"txt,omitempty"`
	// TTL 为响应记录中的 TTL（优先取 SRV，其次 PTR）。
	TTL uint32 `json:"ttl,omitempty"`
}
