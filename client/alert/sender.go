package alert

import (
	"bytes"
	"client/config"
	"client/monitor"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
)

type AlertMessage struct {
	APIKey string          `json:"api_key"`
	Type   string          `json:"type"` // "cpu" / "memory" / "disk"
	Value  monitor.Metrics `json:"value"`
}

func SendAlert(cfg *config.Config, metrics monitor.Metrics) {
	msg := AlertMessage{
		APIKey: cfg.APIKey,
		Type:   "threshold_exceeded",
		Value:  metrics,
	}
	payload, _ := json.Marshal(msg)

	switch strings.ToLower(cfg.Protocol) {
	case "http":
		http.Post(cfg.APIURL, "application/json", bytes.NewBuffer(payload))

	case "udp":
		conn, err := net.Dial("udp", cfg.APIURL)
		if err == nil {
			defer conn.Close()
			conn.Write(payload)
		}

	case "tcp":
		conn, err := net.Dial("tcp", cfg.APIURL)
		if err == nil {
			defer conn.Close()
			conn.Write(payload)
		}

	default:
		fmt.Println("未知协议:", cfg.Protocol)
	}
}
