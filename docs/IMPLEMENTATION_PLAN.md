# mDNS 资产测绘 CLI 实现方案

> 任务来源：[README.md](./README.md)
> 文档日期：2026-08-14

## 1. 任务本质

- **输入**：IP 网段（CIDR）+ 端口范围
- **输出**：该网段 + 端口范围内的 mDNS/DNS-SD 协议资产，每项至少包含 **ip / port / host / 深度识别 banner**
- **深度识别 banner 的本质**：示例中 `model=TS-X64, fwVer=5.2.9, accessType=https, accessPort=86, fwBuildNum=20260214` 这类信息，正是设备厂商（QNAP）通过 mDNS **TXT 记录**公布的设备指纹。因此 **banner 深度 = 把 TXT 记录逐条解析成 key=value 并完整、无截断地呈现**。
- **示例格式参考**：[README.md](./README.md) 中的 `services:` 输出块，为本 CLI 的输出对齐基准。

## 2. 环境实测结论（2026-08-14）

| 项 | 结论 |
|---|---|
| Go 版本 | go1.24.3 windows/amd64，已安装于 `/d/software/GoInstall/bin/go` |
| mDNS 协议层选型 | `github.com/miekg/dns` —— 原生 DNS 报文级，可同时做**组播**与**单播**探测，拿到完整 PTR/SRV/TXT/TTL；比高级库（zeroconf/hashicorp/mdns）可控性更强 |
| GitHub | 远端已存在 `origin = git@github.com:1429222731/code.git`，SSH 认证通过（`Hi 1429222731!`）；该仓库经 GitHub API 未认证探测返回 **HTTP 200 = 公开仓库** → 直接 `git push` 即可，无需 gh CLI / PAT / token |

## 3. 核心方案：双引擎发现，让 CIDR 与端口输入真正生效

### 3.1 组播引擎（标准 DNS-SD 流程，主发现）

1. 绑定并监听组播地址 `224.0.0.251:5353`
2. 发送 PTR 查询 `_services._dns-sd._udp.local`，枚举局域网内全部服务类型
3. 对每个服务类型发起 PTR 查询，获取实例（instance）
4. 对每个实例发起 SRV + TXT 查询，解析端口、目标主机名、TXT 指纹
5. 收集响应，进入统一资产管道

### 3.2 单播引擎（让"IP 网段"输入有意义的关键）

- 对 CIDR 内每个 IP 直接向 `5353/UDP` 单播发送 mDNS 查询
- 大量设备（尤其 QNAP 等 NAS）对单播查询会直接应答
- 工作池并发 + 限速 + 全局超时
- 仅采纳应答 IP ∈ CIDR 的响应

### 3.3 去重与端口过滤

- 双引擎结果按 (IP, 端口, 服务类型) 合并去重
- 仅保留 SRV 端口 ∈ 端口范围的资产（支持 `1-1000` / `1,2,5-9` / `all`）

## 4. 代码结构

```
(仓库根，即 code/)
├── main.go                 CLI 入口：-cidr -ports -timeout -workers -json
├── internal/
│   ├── cli/                CIDR / 端口范围解析与校验
│   ├── mdns/               组播监听 + 单播探测引擎
│   ├── model/              资产模型 Service{Name,IPv4,IPv6,Hostname,TTL,Port,Proto,Type,TXT}
│   ├── parse/              DNS 报文 → Service 资产
│   └── output/             示例格式渲染 + 可选 JSON 输出
├── parse_test.go           用示例数据构造伪报文，断言输出逐字对齐
└── go.mod                  依赖 github.com/miekg/dns
```

## 5. 输出格式（严格对齐示例，保证 banner 深度达标）

每个服务块输出如下结构：

```
<port>/<proto> <type>:            # 无 SRV 端口时退化为 <type>:
Name=<实例名>                      # 直接回显，示例含 [MAC] 后缀
IPv4=x.x.x.x
IPv6=fe80::...                    # 有则输出
Hostname=xxx.local                # SRV 记录目标
TTL=10                            # 响应记录 TTL
model=TS-X64,fwVer=5.2.9,accessType=https,accessPort=86,...   # TXT 记录按逗号连接为一行
```

要点：
- `Name`、`IPv6`、`TTL`、TXT 行均来自真实响应记录，不伪造、不截断
- TXT 指纹行是**深度识别 banner** 的载体，必须完整呈现

## 6. 里程碑节奏（30 分钟可执行）

| 时间段 | 工作 |
|---|---|
| 0–3min | 脚手架、go.mod、CLI 参数解析 |
| 3–12min | 组播引擎 + DNS 报文解析（核心） |
| 12–18min | 单播探测 + 去重 + 端口过滤 |
| 18–23min | 输出格式化 + 用示例构造报文做单测（无真实设备也能验证格式） |
| 23–28min | 本机局域网实测（如扫描 192.168.x.0/24），修问题 |
| 28–30min | `git add/commit/push` 至公开仓库，交付仓库地址 |

## 7. 风险与对策

| 风险 | 对策 |
|---|---|
| Windows 防火墙拦截 UDP 5353 / 组播 | 首次运行若零结果，放行入站或管理员运行；单播引擎兜底 |
| 局域网无真实 mDNS 设备 | 单测用示例伪报文锁定输出格式；实测以 banner 深度与格式为准 |
| CIDR 过大导致单播慢 | 工作池 + 全局超时（默认 10s） |

## 8. 待拍板事项

- **上传仓库**：使用现有公开仓库 `1429222731/code`（零摩擦、已验证可用）**（推荐）**，或另建独立公开仓库（无 gh/token 时需提供 PAT 走 GitHub API）。
