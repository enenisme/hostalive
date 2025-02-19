package scanner

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// HostScanner 主机扫描器结构体
type HostScanner struct {
	Timeout     time.Duration
	Concurrency int
}

// ScanResult 扫描结果结构体
type ScanResult struct {
	IP    string
	Alive bool
}

// Target 表示扫描目标
type Target struct {
	IP   string
	CIDR bool // 是否是CIDR格式
}

// NewHostScanner 创建新的主机扫描器实例
func NewHostScanner(timeout time.Duration, concurrency int) *HostScanner {
	if concurrency <= 0 {
		concurrency = 100 // 默认并发数
	}
	return &HostScanner{
		Timeout:     timeout,
		Concurrency: concurrency,
	}
}

// ParseTarget 解析目标地址
func ParseTarget(target string) (*Target, error) {
	// 检查是否是CIDR格式 (例如: 192.168.1.0/24)
	if strings.Contains(target, "/") {
		_, ipNet, err := net.ParseCIDR(target)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR format: %v", err)
		}
		return &Target{IP: ipNet.String(), CIDR: true}, nil
	}

	// 验证单个IP地址
	if ip := net.ParseIP(target); ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", target)
	}
	return &Target{IP: target, CIDR: false}, nil
}

// Scan 通用扫描方法，支持单个IP和网段
func (s *HostScanner) Scan(target string) ([]ScanResult, error) {
	parsedTarget, err := ParseTarget(target)
	if err != nil {
		return nil, err
	}

	if !parsedTarget.CIDR {
		// 扫描单个IP
		alive := s.IsHostAlive(parsedTarget.IP)
		return []ScanResult{{IP: parsedTarget.IP, Alive: alive}}, nil
	}

	// 扫描网段
	_, ipNet, _ := net.ParseCIDR(parsedTarget.IP)
	return s.scanNetwork(ipNet), nil
}

// scanNetwork 扫描网段
func (s *HostScanner) scanNetwork(ipNet *net.IPNet) []ScanResult {
	var results []ScanResult
	var wg sync.WaitGroup
	var resultMutex sync.Mutex
	semaphore := make(chan struct{}, s.Concurrency)

	// 获取网段的起始IP（跳过网络地址）
	ip := ipNet.IP.Mask(ipNet.Mask)
	ip = incrementIP(ip) // 跳过网络地址

	// 计算最后一个可用IP（排除广播地址）
	lastIP := make(net.IP, len(ip))
	copy(lastIP, ip)
	for i := range lastIP {
		lastIP[i] = ip[i] | ^ipNet.Mask[i]
	}
	lastIP = decrementIP(lastIP) // 排除广播地址

	// 遍历IP地址范围（从第一个可用IP到最后一个可用IP）
	for !ip.Equal(incrementIP(lastIP)) {
		if !ipNet.Contains(ip) {
			continue
		}

		wg.Add(1)
		semaphore <- struct{}{} // 获取信号量

		go func(currentIP net.IP) {
			defer wg.Done()
			defer func() { <-semaphore }() // 释放信号量

			ipStr := currentIP.String()
			alive := s.IsHostAlive(ipStr)

			if alive {
				resultMutex.Lock()
				results = append(results, ScanResult{
					IP:    ipStr,
					Alive: true,
				})
				resultMutex.Unlock()
			}
		}(copyIP(ip))

		ip = incrementIP(ip)
	}

	wg.Wait()
	return results
}

// 新增：decrementIP 函数用于递减IP地址
func decrementIP(ip net.IP) net.IP {
	newIP := copyIP(ip)
	for i := len(newIP) - 1; i >= 0; i-- {
		if newIP[i] > 0 {
			newIP[i]--
			break
		}
		newIP[i] = 255
	}
	return newIP
}

// 辅助函数：递增IP地址
func incrementIP(ip net.IP) net.IP {
	newIP := copyIP(ip)
	for i := len(newIP) - 1; i >= 0; i-- {
		newIP[i]++
		if newIP[i] != 0 {
			break
		}
	}
	return newIP
}

// 辅助函数：复制IP地址
func copyIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

// IsHostAlive 检查主机是否存活
func (s *HostScanner) IsHostAlive(ip string) bool {
	// 只使用 ping 检测
	return s.pingCheck(ip)
}

// pingCheck 使用ICMP ping检测主机
func (s *HostScanner) pingCheck(ip string) bool {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", ip, "-n", "1", "-w", "200")
	case "linux":
		cmd = exec.Command("/bin/sh", "-c", "ping -c 1 "+ip)
	case "darwin":
		cmd = exec.Command("ping", ip, "-c", "1", "-W", "200")
	case "freebsd":
		cmd = exec.Command("ping", "-c", "1", "-W", "200", ip)
	case "openbsd":
		cmd = exec.Command("ping", "-c", "1", "-w", "200", ip)
	case "netbsd":
		cmd = exec.Command("ping", "-c", "1", "-w", "2", ip)
	default:
		cmd = exec.Command("ping", "-c", "1", ip)
	}

	// 执行命令并检查输出中是否包含 TTL
	if output, err := cmd.Output(); err == nil {
		outputStr := strings.ToLower(string(output))
		if strings.Contains(outputStr, "ttl=") {
			fmt.Printf("Host %s is alive\n", ip)
			return true
		}
	}
	return false
}
