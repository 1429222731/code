# mdnsmap

基于 **mDNS / DNS-SD** 协议的局域网资产测绘 CLI（Golang）。

输入 IP 网段与端口范围，输出该范围内 mDNS 协议资产信息：**IP / 端口 / 主机名 / 深度识别 banner**。
深度识别 banner 来自 DNS-SD **TXT 记录**（如 QNAP 的 `model=TS-X64, fwVer=5.2.9, accessType=https,...` 设备指纹）。

## 特性

- **双引擎发现**：组播枚举（`_services._dns-sd._udp.local` → 各服务类型 PTR/SRV/TXT/A/AAAA）+ 对网段内每个 IP 单播探测，让 `-cidr` 输入真正生效
- **端口过滤**：仅保留 SRV 端口落在 `-ports` 范围内的资产
- **深度 banner**：完整呈现 TXT 记录的 key=value 设备指纹，输出格式对齐任务示例
- **多种输出**：对齐示例的文本格式，或 `-json`
- **附带模拟器**：`cmd/mockmdns` 可在无真实设备时广播示例资产用于联调

## 安装 / 构建

```bash
go build -o mdnsmap.exe .
```

## 用法

```bash
# 扫描整个局域网段，保留全部端口
mdnsmap -cidr 192.168.1.0/24

# 指定端口范围 + JSON 输出
mdnsmap -cidr 192.168.1.0/24 -ports 1-65535 -json

# 多个网段、更长时间窗口、调试统计
mdnsmap -cidr 192.168.1.0/24,10.0.0.0/16 -ports 80,443,5000 -timeout 15s -debug
```

### 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-cidr` | 必填 | 目标 IP 网段，逗号分隔多个，如 `192.168.1.0/24` |
| `-ports` | `all` | 保留的端口范围，如 `1-65535` / `80,443` / `1-5,800-900` / `all` |
| `-timeout` | `12s` | 扫描总时长 |
| `-workers` | `200` | 单播探测并发数 |
| `-maxips` | `65536` | 单播探测 IP 总数上限 |
| `-json` | `false` | JSON 输出 |
| `-debug` | `false` | 输出收发统计，便于排障 |

## 输出示例

```
services:
548/tcp afpovertcp:
Name=slw-nas(AFP)
IPv4=192.168.1.100
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=120
5000/tcp qdiscover:
Name=slw-nas
IPv4=192.168.1.100
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=120
accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214
```

## 联调模拟器

无真实 mDNS 设备时，先启动模拟器广播示例资产，再扫描即可看到结果：

```bash
go run ./cmd/mockmdns -ip 192.168.1.200
mdnsmap -cidr 192.168.1.0/24 -ports all
```

## 测试

```bash
go test ./...
```

## 目录结构

```
main.go                    CLI 入口
cmd/mockmdns/              mDNS 应答模拟器（联调用）
internal/
  cli/                     CIDR 解析与配置
  portrange/               端口范围解析
  model/                   资产数据模型
  parse/                   DNS 报文 -> 记录
  mdns/                    组播+单播引擎、聚合与过滤
  output/                  示例格式 / JSON 渲染
```

## 说明

- mDNS 运行于 UDP 5353；Windows 上若收不到应答，需放行防火墙入站 UDP 5353（或管理员运行）。
- 端口为 0 的条目表示仅有 PTR 记录、未解析到 SRV 端口，仅在 `-ports all` 时输出。
