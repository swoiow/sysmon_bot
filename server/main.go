package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"gopkg.in/yaml.v3"
)

//go:embed index.html
var indexHtml []byte

// -------------------- 数据结构 --------------------

type DeviceInfo struct {
	IP       string `json:"ip"`
	LastSeen string `json:"lastSeen"`
}

type LogEntry struct {
	Time string `json:"time"`
	Msg  string `json:"msg"`
}

type ServerState struct {
	sync.RWMutex
	Devices map[string]DeviceInfo `json:"devices"`
	Logs    []LogEntry            `json:"logs"`
	Keys    map[string]string     `json:"keys"` // api_key -> core_key
}

var state = ServerState{
	Devices: make(map[string]DeviceInfo),
	Logs:    make([]LogEntry, 0, 100),
	Keys:    make(map[string]string),
}

type ServerConfig struct {
	Webhook struct {
		URL     string            `yaml:"url"`
		Headers map[string]string `yaml:"headers"`
	} `yaml:"webhook"`
}
var serverConfig ServerConfig

const stateFile = "server_state.json"
const maxAge = 60

// -------------------- 主入口 --------------------

func main() {
	loadServerConfig()
	loadStateFromDisk()

	log.Println("🌐 Starting server...")
	go persistLoop()

	go startHTTP(":9000")
	go startUDP(":9001")
	go startTCP(":9002")

	select {}
}

// -------------------- 状态持久化 --------------------

func persistLoop() {
	for {
		time.Sleep(30 * time.Second)
		persistStateToDisk()
	}
}

func persistStateToDisk() {
	state.RLock()
	defer state.RUnlock()
	f, _ := os.Create(stateFile)
	defer f.Close()
	json.NewEncoder(f).Encode(state)
	log.Println("🔒 状态已保存到磁盘")
}

func loadStateFromDisk() {
	f, err := os.Open(stateFile)
	if err != nil {
		log.Println("⚠️ 无法加载状态文件:", err)
		return
	}
	defer f.Close()
	json.NewDecoder(f).Decode(&state)
	log.Println("🔄 状态已从磁盘加载")
}

func loadServerConfig() {
	data, err := os.ReadFile("server_config.yaml")
	if err != nil {
		log.Println("⚠️ 无法加载 webhook 配置:", err)
		return
	}
	yaml.Unmarshal(data, &serverConfig)
	log.Println("🔧 Webhook 配置已加载")
}

// -------------------- HTTP 服务 --------------------

func startHTTP(addr string) {
	http.HandleFunc("/", serveIndex)
	http.HandleFunc("/api/status", getStatus)
	http.HandleFunc("/api/key", handleKeyCreate)
	http.HandleFunc("/api/key/", handleKeyDelete)
	log.Println("🌐 HTTP 监听中，端口:", addr)
	http.ListenAndServe(addr, nil)
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write(indexHtml)
	log.Println("🔗 访问了 /")
}

func getStatus(w http.ResponseWriter, r *http.Request) {
	state.RLock()
	defer state.RUnlock()
	log.Println("🔍 获取状态信息")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(state)
}

func handleKeyCreate(w http.ResponseWriter, r *http.Request) {
	apiKey := "AK-" + generateSecureKey(22)
	coreKey := generateSecureKey(20)
	now := time.Now().Format("2025-04-23 00:34:24")

	state.Lock()
	state.Keys[apiKey] = coreKey
	state.Devices[apiKey] = DeviceInfo{IP: "-", LastSeen: now}
	state.Unlock()

	log.Printf("✅ 创建了新API Key: %s", apiKey)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"api_key":  apiKey,
		"core_key": coreKey,
	})
}

func handleKeyDelete(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/api/key/")
	state.Lock()
	delete(state.Keys, key)
	delete(state.Devices, key)
	state.Unlock()
	log.Printf("✅ 删除了API Key: %s", key)
	w.WriteHeader(200)
}

// -------------------- 数据接收 --------------------

func handlePacket(data []byte, ip string) {
	log.Printf("🔄 接收到来自 %s 的数据: %s", ip, string(data))

	if !verifyRequest(data) {
		log.Println("❌ 签名校验失败")
		return
	}

	var m map[string]interface{}
	json.Unmarshal(data, &m)
	apiKey := m["api_key"].(string)

	now := time.Now().Format("2025-04-23 00:34:24")

	state.Lock()
	state.Devices[apiKey] = DeviceInfo{IP: ip, LastSeen: now}
	state.Logs = append(state.Logs, LogEntry{
		Time: now,
		Msg:  fmt.Sprintf("[%s] %s", apiKey, string(data)),
	})
	if len(state.Logs) > 100 {
		state.Logs = state.Logs[1:]
	}
	state.Unlock()

	log.Printf("✅ 已处理并记录日志，API Key: %s", apiKey)

	go forwardToExternal(data)
}

func forwardToExternal(data []byte) {
	if serverConfig.Webhook.URL == "" {
		log.Println("⚠️ 未配置 webhook.url，跳过外发")
		return
	}

	// 构造 JSON payload
	payloadMap := map[string]string{
		"text": string(data),
	}
	payload, _ := json.Marshal(payloadMap)

	// 构造 HTTP 请求
	req, err := http.NewRequest("POST", serverConfig.Webhook.URL, bytes.NewBuffer(payload))
	if err != nil {
		log.Println("❌ 构建请求失败:", err)
		return
	}

	for k, v := range serverConfig.Webhook.Headers {
		req.Header.Set(k, v)
	}

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("❌ webhook 发送失败:", err)
		return
	}
	defer resp.Body.Close()

	log.Printf("✅ Webhook 返回 %s", resp.Status)
}

func startUDP(addr string) {
	udpAddr, _ := net.ResolveUDPAddr("udp", addr)
	conn, _ := net.ListenUDP("udp", udpAddr)
	log.Println("📡 UDP listening on", addr)
	buf := make([]byte, 4096)
	for {
		n, addr, _ := conn.ReadFromUDP(buf)
		handlePacket(buf[:n], addr.String())
	}
}

func startTCP(addr string) {
	ln, _ := net.Listen("tcp", addr)
	log.Println("🔌 TCP listening on", addr)
	for {
		conn, _ := ln.Accept()
		go func(c net.Conn) {
			defer c.Close()
			data, _ := io.ReadAll(c)
			handlePacket(data, c.RemoteAddr().String())
		}(conn)
	}
}

// -------------------- 签名校验 --------------------

func verifyRequest(data []byte) bool {
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		log.Println("❌ JSON 解码失败:", err)
		return false
	}
	apiKey, _ := m["api_key"].(string)
	sign, _ := m["sign"].(string)
	tsf, ok := m["timestamp"].(float64)
	if !ok || apiKey == "" || sign == "" {
		log.Println("❌ 请求缺少必要字段")
		return false
	}

	ts := int64(tsf)
	if abs(time.Now().Unix()-ts) > maxAge {
		log.Println("❌ 签名过期")
		return false
	}

	state.RLock()
	coreKey := state.Keys[apiKey]
	state.RUnlock()

	expected := md5Hex(apiKey + fmt.Sprintf("%d", ts) + coreKey)
	return strings.EqualFold(expected, sign)
}

func md5Hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

func generateSecureKey(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)[:length]
}
