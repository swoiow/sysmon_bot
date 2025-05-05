package monitor

import (
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"log"
	"math"
)

type Metrics struct {
	CPU    float64            `json:"cpu"`
	Memory float64            `json:"memory"`
	Disks  map[string]float64 `json:"disks"` // key = mountpoint, value = usage%
}

func CollectMetrics() Metrics {
	cpuPercent, _ := cpu.Percent(0, false)
	memStat, _ := mem.VirtualMemory()

	partitions, _ := disk.Partitions(true)
	diskUsages := make(map[string]float64)

	for _, p := range partitions {
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil || usage.Total == 0 {
			continue
		}

		// 按设备名记录（而非挂载点）
		//diskUsages[p.Device] = Round(usage.UsedPercent)
		// 按挂载点记录（而非设备名）
		diskUsages[p.Mountpoint] = Round(usage.UsedPercent)
	}

	if len(cpuPercent) == 0 {
		log.Println("未能获取CPU信息")
	}

	return Metrics{
		CPU:    Round(cpuPercent[0]),
		Memory: Round(memStat.UsedPercent),
		Disks:  diskUsages,
	}
}

func Round(val float64) float64 {
	return math.Round(val*100000) / 100000
}
