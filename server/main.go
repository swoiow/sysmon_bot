package main

import (
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
)

//go:embed index.html
var indexHtml []byte

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

const stateFile = "server_state.json"
const maxAge = 60

func main() {
	loadStateFromDisk()
	go persistLoop()
	go startHTTP(":9000")
	go startUDP(":9001")
	go startTCP(":9002")

	select {}
}

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
}

func loadStateFromDisk() {
	f, err := os.Open(stateFile)
	if err != nil {
		return
	}
	defer f.Close()
	json.NewDecoder(f).Decode(&state)
}

// ----------------- HTTP -----------------

func startHTTP(addr string) {
	http.HandleFunc("/", serveIndex)
	http.HandleFunc("/api/status", getStatus)
	http.HandleFunc("/api/key", handleKeyCreate)
	http.HandleFunc("/api/key/", handleKeyDelete)
	log.Println("🌐 HTTP listening on", addr)
	http.ListenAndServe(addr, nil)
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write(indexHtml)
}

func getStatus(w http.ResponseWriter, r *http.Request) {
	state.RLock()
	defer state.RUnlock()
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
	w.WriteHeader(200)
}

// ----------------- 签名校验 -----------------

func verifyRequest(data []byte) bool {
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return false
	}
	apiKey, _ := m["api_key"].(string)
	sign, _ := m["sign"].(string)
	tsf, ok := m["timestamp"].(float64)
	if !ok || apiKey == "" || sign == "" {
		return false
	}

	ts := int64(tsf)
	if abs(time.Now().Unix()-ts) > maxAge {
		return false
	}

	state.RLock()
	coreKey := state.Keys[apiKey]
	state.RUnlock()

	if coreKey == "" {
		return false
	}

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

// ----------------- 接收处理 -----------------

func handlePacket(data []byte, ip string) {
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

	go forwardToExternal(data)
}

func forwardToExternal(data []byte) {
	fmt.Println("📤 Forward to external system (TODO):", string(data))
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
