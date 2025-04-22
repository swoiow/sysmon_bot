package client

import (
	"client/alert"
	"client/config"
	"client/monitor"
	"client/storage"
	"log"
	"time"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	store := storage.NewLocalStore()
	ticker := time.NewTicker(5 * time.Minute)

	for {
		metrics := monitor.CollectMetrics()

		store.Append(metrics)

		avg := store.AverageLastHour()
		log.Printf("当前值: CPU: %.2f%% Mem: %.2f%% Disk: %.2f%%", metrics.CPU, metrics.Memory, metrics.Disk)
		log.Printf("过去1小时平均: CPU: %.2f%% Mem: %.2f%% Disk: %.2f%%", avg.CPU, avg.Memory, avg.Disk)

		if avg.CPU > cfg.Thresholds.CPUUsage ||
			avg.Memory > cfg.Thresholds.MemoryUsage ||
			avg.Disk > cfg.Thresholds.DiskUsage {

			alert.SendAlert(cfg, avg)
		}

		<-ticker.C
	}
}
