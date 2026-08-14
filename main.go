// mdnsmap 是一个基于 mDNS/DNS-SD 的局域网资产测绘 CLI。
//
// 用法示例：
//
//	mdnsmap -cidr 192.168.1.0/24 -ports 1-65535
//	mdnsmap -cidr 192.168.1.0/24 -ports 80,443,5000 -timeout 15s -json
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/1429222731/code/internal/cli"
	"github.com/1429222731/code/internal/mdns"
	"github.com/1429222731/code/internal/output"
)

func main() {
	var (
		cidrStr = flag.String("cidr", "", "目标 IP 网段，支持逗号分隔多个，如 192.168.1.0/24")
		portStr = flag.String("ports", "all", "保留的服务端口范围，如 1-65535 / 80,443 / 1-5,800-900 / all")
		timeout = flag.Duration("timeout", 12*time.Second, "扫描总时长")
		workers = flag.Int("workers", 200, "单播探测并发数")
		jsonOut = flag.Bool("json", false, "以 JSON 输出")
		maxIPs  = flag.Int("maxips", 65536, "单播探测 IP 总数上限")
		debug   = flag.Bool("debug", false, "输出接收统计用于排障")
	)
	flag.Parse()

	cfg, err := cli.Parse(*cidrStr, *portStr, *timeout, *workers, *jsonOut, *maxIPs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "参数错误:", err)
		flag.Usage()
		os.Exit(2)
	}

	sc, err := mdns.New(mdns.Config{
		CIDRs:   cfg.CIDRs,
		Ports:   cfg.Ports,
		Timeout: cfg.Timeout,
		Workers: cfg.Workers,
		MaxIPs:  cfg.MaxIPs,
		Debug:   *debug,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "初始化失败:", err)
		os.Exit(2)
	}

	fmt.Fprintln(os.Stderr, "[*] 开始 mDNS 资产测绘:", cfg.CIDRs[0], "端口:", cfg.Ports.String(), "窗口:", cfg.Timeout)
	services, err := sc.Run(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "扫描失败:", err)
		os.Exit(1)
	}

	if cfg.JSON {
		if err := output.RenderJSON(services, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "输出失败:", err)
			os.Exit(1)
		}
	} else {
		if err := output.Render(services, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "输出失败:", err)
			os.Exit(1)
		}
	}
	fmt.Fprintln(os.Stderr, "[*] 完成，共发现", len(services), "条服务资产")
	if *debug {
		st := sc.Stats()
		fmt.Fprintf(os.Stderr, "[*] debug 统计: 发出查询=%d 收到报文=%d 应答=%d 发现类型=%d\n",
			st.Queries, st.Packets, st.Responses, st.Types)
	}
}
