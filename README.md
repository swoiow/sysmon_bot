# SysMonBot - 系统监控告警机器人（跨平台）

SysMonBot 是一套基于 Golang 编写的轻量级 **客户端-服务端系统监控告警框架**，支持 Linux、Windows、macOS 多平台构建，采用签名校验机制保障传输安全，适用于公司内网或混合网络的主机状态监控。

---

## 📦 项目结构

```
.
├── client/                  # 客户端：每5分钟采集一次CPU/内存/磁盘
│   ├── main.go              # 启动入口
│   ├── config/              # 配置加载模块
│   ├── monitor/             # 系统信息采集
│   ├── storage/             # 最近1小时内数据的本地缓存与平均计算
│   └── alert/               # 超阈值发送警报（含签名机制）
│
├── server/                  # 服务端：接收告警数据 + 管理 UI
│   ├── main.go              # 启动 HTTP + UDP + TCP Server
│   └── index.html           # Vue3 单页 Web 管理界面（CDN 直引）
│
├── .github/workflows/       # GitHub Actions 自动化构建与发布脚本
│   └── build.yml
```

---

## 🧠 系统设计思路

### ✅ Client（每台主机运行）
- 每 5 分钟采集 CPU / 内存 / 磁盘 使用率
- 计算过去 1 小时平均值
- 若超过配置阈值，构造签名报文并通过 HTTP/UDP/TCP 向服务端发送

### ✅ Server（集中管理 + 接收数据）
- 接收客户端上报（支持 HTTP、UDP、TCP）
- 校验签名 `md5(api_key + timestamp + core_key)`，防止伪造与重放
- 显示已注册设备、最近IP、报文日志
- 提供 Web UI 创建/删除 key，并返回 core_key

---

## 🔐 安全机制

- **签名机制：**
  - 客户端发送报文时计算：
    ```
    sign = md5(api_key + timestamp + core_key)
    ```
  - 服务端验证时间戳 ±60 秒范围内有效
- **密钥管理：**
  - 每个 API Key 对应一个 core_key
  - 支持同一 IP 多 Key，不反查绑定，避免 NAT 影响

---

## ⚙️ 配置说明（Client）

```yaml
api_key: "xxx"
core_key: "yyy"
api_url: "127.0.0.1:9000"
protocol: "http"  # 或 udp / tcp

thresholds:
  cpu_usage: 80.0
  memory_usage: 85.0
  disk_usage: 90.0
```

配置路径默认：
- Linux: `/etc/sysmon_bot/config.yaml`
- Windows: `C:\ProgramData\SysMonBot\config.yaml`

---

## 🖥️ Web UI 管理界面

访问 `http://localhost:9000` 查看：

- ✅ 创建 API Key（自动生成）
- ✅ 查看设备状态（IP、最后活动时间）
- ✅ 删除无效 Key
- ✅ 查看最近报文日志（含时间）

> UI 使用 Vue3 + CDN，嵌入 Go 二进制中无需前端部署。

---

## 🚀 GitHub Actions 自动化构建

- 使用 **Docker 构建二进制文件**（而非宿主交叉编译）
- 支持平台：
  - linux-amd64
  - windows-amd64
  - darwin-amd64
- 构建产物压缩为 zip
- 自动发布：
  - tag 触发：发布 Release 附件
  - 所有构建：上传临时 Artifacts（保存 3 天）

> 构建配置详见 [.github/workflows/build.yml](.github/workflows/build.yml)

---

## 💡 未来功能规划

- [ ] 支持 webhook 发送至飞书 / 企业微信
- [ ] 设备在线/离线实时状态识别
- [ ] 客户端守护进程支持 + 重启策略
- [ ] 系统资源变化趋势可视化（Grafana 插件？）

---

## 📄 License

MIT License
