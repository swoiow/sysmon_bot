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
	var sum monitor.Metrics
	var count int

	for _, dp := range s.data {
		if now.Sub(dp.TS) <= time.Hour {
			sum.CPU += dp.Metrics.CPU
			sum.Memory += dp.Metrics.Memory
			sum.Disk += dp.Metrics.Disk
			count++
		}
	}

	if count == 0 {
		return monitor.Metrics{}
	}

	return monitor.Metrics{
		CPU:    sum.CPU / float64(count),
		Memory: sum.Memory / float64(count),
		Disk:   sum.Disk / float64(count),
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
