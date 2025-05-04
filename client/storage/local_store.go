package storage

import (
	"client/monitor"
	"time"
)

type dataPoint struct {
	TS      time.Time
	Metrics monitor.Metrics
}

type LocalStore struct {
	data []dataPoint
}

func NewLocalStore() *LocalStore {
	return &LocalStore{}
}

func (s *LocalStore) Append(m monitor.Metrics) {
	now := time.Now()
	s.data = append(s.data, dataPoint{TS: now, Metrics: m})
	s.gc(now)
}

func (s *LocalStore) AverageLastHour() monitor.Metrics {
	now := time.Now()
	var sumCPU, sumMem float64
	diskSums := make(map[string]float64)
	count := 0

	for _, dp := range s.data {
		if now.Sub(dp.TS) <= time.Hour {
			sumCPU += dp.Metrics.CPU
			sumMem += dp.Metrics.Memory
			for mount, usage := range dp.Metrics.Disks {
				diskSums[mount] += usage
			}
			count++
		}
	}

	if count == 0 {
		return monitor.Metrics{}
	}

	avgDisks := make(map[string]float64)
	for mount, total := range diskSums {
		avgDisks[mount] = total / float64(count)
	}

	return monitor.Metrics{
		CPU:    sumCPU / float64(count),
		Memory: sumMem / float64(count),
		Disks:  avgDisks,
	}
}

func (s *LocalStore) gc(now time.Time) {
	cutoff := now.Add(-1 * time.Hour)
	var filtered []dataPoint
	for _, dp := range s.data {
		if dp.TS.After(cutoff) {
			filtered = append(filtered, dp)
		}
	}
	s.data = filtered
}
