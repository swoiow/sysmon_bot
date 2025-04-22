package monitor

import (
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"log"
)

type Metrics struct {
	CPU    float64
	Memory float64
	Disk   float64
}

func CollectMetrics() Metrics {
	cpuPercent, _ := cpu.Percent(0, false)
	memStat, _ := mem.VirtualMemory()
	diskStat, _ := disk.Usage("/")

	if len(cpuPercent) == 0 {
		log.Println("未能获取CPU信息")
	}

	return Metrics{
		CPU:    cpuPercent[0],
		Memory: memStat.UsedPercent,
		Disk:   diskStat.UsedPercent,
	}
}
