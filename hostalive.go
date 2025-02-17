package hostalive

import (
	"sort"
	"time"

	"github.com/enenisme/hostalive/scanner"
)

type HostAlive struct {
	IP          string
	CIDR        bool // 是否是CIDR格式
	timeOut     int
	concurrency int
}

type ScanResult struct {
	IP    string
	Alive bool
}

func NewHostAlive(ip string, cidr bool, timeOut int, concurrency int) *HostAlive {
	return &HostAlive{
		IP:          ip,
		CIDR:        cidr,
		timeOut:     timeOut,
		concurrency: concurrency,
	}
}

func (h *HostAlive) HostAlive() ([]ScanResult, error) {
	// 示例1：扫描单个IP
	scanner := scanner.NewHostScanner(time.Second*time.Duration(h.timeOut), h.concurrency)

	var scannerResults []ScanResult

	results, err := scanner.Scan(h.IP)
	if err != nil {
		return nil, err
	}

	// 对结果进行排序
	sort.Slice(results, func(i, j int) bool {
		return results[i].IP < results[j].IP
	})

	for _, result := range results {
		if result.Alive {
			scannerResults = append(scannerResults, ScanResult{IP: result.IP, Alive: result.Alive})
		}
	}

	return scannerResults, nil

}
