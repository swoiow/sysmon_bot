package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed index.html
var indexHtml []byte

//go:embed assets/*
var embeddedAssets embed.FS

// -------------------- 常量与元信息 --------------------

const (
	AppName    = "SysMonBot"
	AppVersion = "1.0.0"
	AppAuthor  = "Your Name"

	stateFile = "server_state.json"
	maxAge    = 60
)

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
		Platform string            `yaml:"platform"`
		URL      string            `yaml:"url"`
		Headers  map[string]string `yaml:"headers"`
	} `yaml:"webhook"`
}

var serverConfig ServerConfig

// -------------------- 主函数入口 --------------------

func init() {
	mime.AddExtensionType(".js", "application/javascript")
}

func main() {
	log.Printf("Program: %s, Version: %s, (%s)", AppName, AppVersion, AppAuthor)

	loadServerConfig()
	loadStateFromDisk()

	log.Println("🌐 Starting server...")
	go persistLoop()

	go startHTTP(":9000")
	go startUDP(":9001")
	go startTCP(":9002")

	select {}
}

// -------------------- 状态管理 --------------------

func persistLoop() {
	for {
		time.Sleep(30 * time.Second)
		persistStateToDisk()
	}
}

func persistStateToDisk() {
	state.RLock()
	defer state.RUnlock()

	f, err := os.Create(stateFile)
	if err != nil {
		log.Printf("❌ 无法保存状态文件: %v", err)
		return
	}
	defer f.Close()

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		log.Printf("❌ 状态序列化失败: %v", err)
		return
	}
	f.Write(data)
	log.Println("🔒 状态已保存到磁盘")
}

func loadStateFromDisk() {
	f, err := os.Open(stateFile)
	if err != nil {
		log.Println("⚠️ 无法加载状态文件:", err)
		return
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(&state); err != nil {
		log.Println("⚠️ 状态文件解码失败:", err)
		return
	}
	log.Println("🔄 状态已从磁盘加载")
}

func getDefaultServerConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "server_config.yaml"
	}
	return filepath.Join(dir, "SysMonBot", "server_config.yaml")
}

func loadServerConfig() {
	path := getDefaultServerConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("⚠️ 无法加载配置 %s: %v", path, err)
		return
	}
	if err := yaml.Unmarshal(data, &serverConfig); err != nil {
		log.Printf("❌ 配置解析失败: %v", err)
		return
	}
	log.Printf("✅ 加载 server_config.yaml 成功: %s", path)
}

// -------------------- HTTP 服务 --------------------

func startHTTP(addr string) {
	http.HandleFunc("/", serveIndex)
	http.HandleFunc("/api/status", getStatus)
	http.HandleFunc("/api/key", handleKeyCreate)
	http.HandleFunc("/api/key/", handleKeyDelete)
	http.HandleFunc("/api/report", handleBeat)

	assetsFS, err := fs.Sub(embeddedAssets, "assets")
	if err != nil {
		log.Fatalf("❌ 嵌入资源子路径失败: %v", err)
	}
	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(assetsFS))))

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	log.Println("🌐 HTTP 监听中，端口:", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("❌ HTTP 服务启动失败: %v", err)
	}
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write(indexHtml)
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
	now := time.Now().Format("2006-01-02 15:04:05")

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

func handleBeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	log.Printf("🔔 收到 HTTP POST 报文: %s", string(body))
	handlePacket(body, r.RemoteAddr)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// -------------------- 网络服务 --------------------

func startUDP(addr string) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("❌ 无法解析UDP地址: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("❌ 无法启动UDP监听: %v", err)
	}
	log.Println("📡 UDP listening on", addr)
	buf := make([]byte, 8192)
	for {
		n, addr, _ := conn.ReadFromUDP(buf)
		handlePacket(buf[:n], addr.String())
	}
}

func startTCP(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("❌ 无法启动TCP监听: %v", err)
	}
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

// -------------------- 数据处理 --------------------

func handlePacket(data []byte, ip string) {
	log.Printf("🔄 接收到来自 %s 的数据: %s", ip, string(data))

	if !verifyRequest(data) {
		log.Println("❌ 签名校验失败")
		return
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		log.Println("❌ 报文 JSON 解码失败:", err)
		return
	}
	apiKeyRaw, ok := m["api_key"]
	apiKey, ok2 := apiKeyRaw.(string)
	if !ok || !ok2 {
		log.Println("❌ 无效的 api_key 字段")
		return
	}

	now := time.Now().Format("2006-01-02 15:04:05")

	state.Lock()
	state.Devices[apiKey] = DeviceInfo{IP: ip, LastSeen: now}
	state.Logs = append(state.Logs, LogEntry{Time: now, Msg: fmt.Sprintf("[%s] %s", apiKey, string(data))})
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

	var payload []byte
	var err error

	switch strings.ToLower(serverConfig.Webhook.Platform) {
	case "lark":
		payload, err = buildLarkPayload(data)
	case "dingtalk":
		payload, err = buildDingTalkPayload(data)
	case "wechat":
		payload, err = buildWeComPayload(data)
	default:
		payload, err = json.Marshal(map[string]string{"text": string(data)})
	}

	if err != nil {
		log.Println("❌ 构造 webhook payload 失败:", err)
		return
	}

	req, err := http.NewRequest("POST", serverConfig.Webhook.URL, bytes.NewBuffer(payload))
	if err != nil {
		log.Println("❌ 构建请求失败:", err)
		return
	}
	for k, v := range serverConfig.Webhook.Headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("❌ webhook 发送失败:", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("✅ Webhook 返回 %s", resp.Status)
}

// -------------------- 工具函数 --------------------

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
