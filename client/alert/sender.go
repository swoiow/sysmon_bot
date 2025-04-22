package alert

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"client/config"
	"client/monitor"
)

func SendAlert(cfg *config.Config, metrics monitor.Metrics) {
	ts := time.Now().Unix()
	sign := md5Hex(cfg.APIKey + strconv.FormatInt(ts, 10) + cfg.CoreKey)

	msg := map[string]interface{}{
		"api_key":   cfg.APIKey,
		"timestamp": ts,
		"sign":      sign,
		"cpu":       metrics.CPU,
		"memory":    metrics.Memory,
		"disk":      metrics.Disk,
	}

	payload, _ := json.Marshal(msg)

	switch strings.ToLower(cfg.Protocol) {
	case "http":
		http.Post("http://"+cfg.APIURL, "application/json", bytes.NewBuffer(payload))

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

func md5Hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}
