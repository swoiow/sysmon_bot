package config

import (
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"runtime"
)

type Config struct {
	APIKey     string     `yaml:"api_key"`
	CoreKey    string     `yaml:"core_key"`
	APIURL     string     `yaml:"api_url"`
	Protocol   string     `yaml:"protocol"`
	Interval   int64      `yaml:"interval"`
	Thresholds Thresholds `yaml:"thresholds"`
}

type Thresholds struct {
	CPUUsage    float64 `yaml:"cpu_usage"`
	MemoryUsage float64 `yaml:"memory_usage"`
	DiskUsage   float64 `yaml:"disk_usage"`
}

func DefaultConfigPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "SysMonBot", "config.yaml")
	}
	return "/etc/sysmon_bot/config.yaml"
}

func LoadConfig() (*Config, error) {
	path := DefaultConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	return &cfg, err
}
