package main

import (
	"client/alert"
	"client/config"
	"client/monitor"
	"client/storage"
	"log"
	"time"
)

func main() {
	log.Printf("Program: %s, Version: %s, (%s)", __NAME__, __VERSION__, __AUTHOR__)

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	interval := time.Duration(5) // 默认值：5分钟
	if cfg.Interval > 0 {
		interval = time.Duration(cfg.Interval)
	}
	store := storage.NewLocalStore()
	ticker := time.NewTicker(interval * time.Minute)

	for {
		metrics := monitor.CollectMetrics()
		store.Append(metrics)
		avg := store.AverageLastHour()

		log.Printf("当前值: CPU: %.2f%% Mem: %.2f%%", metrics.CPU, metrics.Memory)
		log.Printf("过去1小时平均: CPU: %.2f%% Mem: %.2f%%", avg.CPU, avg.Memory)

		trigger := avg.CPU > cfg.Thresholds.CPUUsage ||
			avg.Memory > cfg.Thresholds.MemoryUsage

		for mount, usage := range avg.Disks {
			log.Printf("挂载点 [%s] 平均磁盘使用率: %.5f%%", mount, usage)
			if usage > cfg.Thresholds.DiskUsage {
				trigger = true
			}
		}

		if trigger {
			alert.SendAlert(cfg, avg)
		}

		<-ticker.C
	}
}
