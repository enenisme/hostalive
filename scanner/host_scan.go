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
	resultChan := make(chan ScanResult)
	semaphore := make(chan struct{}, s.Concurrency)

	// 获取网段的第一个和最后一个IP
	firstIP := ipNet.IP
	mask := ipNet.Mask
	networkSize := addressCount(mask) - 2 // 减去网络地址和广播地址

	go func() {
		for ip := incrementIP(firstIP); networkSize > 0; ip = incrementIP(ip) {
			wg.Add(1)
			go func(ip net.IP) {
				defer wg.Done()
				semaphore <- struct{}{}        // 获取信号量
				defer func() { <-semaphore }() // 释放信号量

				ipStr := ip.String()
				alive := s.IsHostAlive(ipStr)
				resultChan <- ScanResult{
					IP:    ipStr,
					Alive: alive,
				}
			}(copyIP(ip))
			networkSize--
		}
		wg.Wait()
		close(resultChan)
	}()

	// 收集结果
	for result := range resultChan {
		results = append(results, result)
	}

	return results
}

// 辅助函数：计算网段中的地址数量
func addressCount(mask net.IPMask) int {
	ones, bits := mask.Size()
	return 1 << uint(bits-ones)
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
	// 首先尝试 ICMP ping
	if s.pingCheck(ip) {
		return true
	}

	// 如果 ICMP 失败，尝试 TCP 端口探测
	return s.tcpCheck(ip)
}

// pingCheck 使用 ICMP ping 检测主机
func (s *HostScanner) pingCheck(ip string) bool {
	var cmd *exec.Cmd

	// 根据操作系统选择不同的 ping 命令
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "1", "-w", "1000", ip)
	default: // Linux, macOS, etc.
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	}

	// 执行 ping 命令
	err := cmd.Run()
	return err == nil
}

// tcpCheck 使用 TCP 连接检测主机
func (s *HostScanner) tcpCheck(ip string) bool {
	// 常用端口列表
	commonPorts := []string{"80", "443", "22", "21", "3389"}

	for _, port := range commonPorts {
		address := net.JoinHostPort(ip, port)
		conn, err := net.DialTimeout("tcp", address, s.Timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}

	return false
}
