package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/1429222731/code/internal/model"
)

// qnapExample 按 docs/README.md 示例构建同一台 QNAP NAS 的 6 条服务。
func qnapExample() []*model.Service {
	host := "slw-nas.local"
	ip6 := "fe80::265e:beff:fe69:a313"
	return []*model.Service{
		{Type: "workstation", Proto: "tcp", Instance: "slw-nas [24:5e:be:69:a3:13]", Hostname: host, Port: 9, IPv4: []string{"x.x.x.x"}, IPv6: []string{ip6}, TTL: 10},
		{Type: "http", Proto: "tcp", Instance: "slw-nas", Hostname: host, Port: 5000, IPv4: []string{"x.x.x.x"}, IPv6: []string{ip6}, TTL: 10, TXT: []string{"path=/"}},
		{Type: "smb", Proto: "tcp", Instance: "slw-nas", Hostname: host, Port: 445, IPv4: []string{"x.x.x.x"}, IPv6: []string{ip6}, TTL: 10},
		{Type: "qdiscover", Proto: "tcp", Instance: "slw-nas", Hostname: host, Port: 5000, IPv4: []string{"x.x.x.x"}, IPv6: []string{ip6}, TTL: 10, TXT: []string{"accessType=https", "accessPort=86", "model=TS-X64", "displayModel=TS-464C", "fwVer=5.2.9", "fwBuildNum=20260214"}},
		{Type: "device-info", Proto: "tcp", Instance: "slw-nas(AFP)", Hostname: host, Port: 0, IPv4: []string{"x.x.x.x"}, IPv6: []string{ip6}, TTL: 10, TXT: []string{"model=Xserve"}},
		{Type: "afpovertcp", Proto: "tcp", Instance: "slw-nas(AFP)", Hostname: host, Port: 548, IPv4: []string{"x.x.x.x"}, IPv6: []string{ip6}, TTL: 10},
	}
}

func TestRenderMatchesExampleDepth(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(qnapExample(), &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	// 期望按类型名排序后的输出，字段与 docs/README.md 示例逐字一致。
	want := `services:
548/tcp afpovertcp:
Name=slw-nas(AFP)
IPv4=x.x.x.x
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
device-info:
Name=slw-nas(AFP)
IPv4=x.x.x.x
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
model=Xserve
5000/tcp http:
Name=slw-nas
IPv4=x.x.x.x
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
path=/
5000/tcp qdiscover:
Name=slw-nas
IPv4=x.x.x.x
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214
445/tcp smb:
Name=slw-nas
IPv4=x.x.x.x
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
9/tcp workstation:
Name=slw-nas [24:5e:be:69:a3:13]
IPv4=x.x.x.x
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
`
	if got != want {
		t.Errorf("Render 输出与示例不符。\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRenderNoServices(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(nil, &buf); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), "services:\n"; got != want {
		t.Errorf("空结果输出 = %q, want %q", got, want)
	}
}

func TestRenderJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(qnapExample(), &buf); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	for _, key := range []string{`"qdiscover"`, `"model=Xserve"`, `"accessType=https"`, `"TS-X64"`, `"slw-nas [24:5e:be:69:a3:13]"`} {
		if !strings.Contains(s, key) {
			t.Errorf("JSON 缺少字段 %s:\n%s", key, s)
		}
	}
}
