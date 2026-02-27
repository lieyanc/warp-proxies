# warp-proxies

多账户 Cloudflare WARP 代理服务，单二进制文件，内置 Web 管理面板。

基于 [sing-box](https://github.com/SagerNet/sing-box) 引擎，通过 WireGuard 隧道提供 SOCKS5 和 HTTP 代理，支持多 WARP 账户自动注册、负载均衡和随机轮换。

## 特性

- **一键注册** — 通过 WebUI 或 API 直接注册 Cloudflare WARP 账户，无需 wgcf 等外部工具
- **多账户管理** — 支持批量创建、启用/禁用、删除 WARP 账户
- **双协议代理** — 同时提供 SOCKS5 和 HTTP/HTTPS 代理入站
- **智能出站** — 双层出站架构：Selector → URLTest → WireGuard×N
- **轮换模式** — `urltest` 自动延迟测试选优 / `random` 定时随机切换
- **Web 管理面板** — 内置 SPA 管理界面，Basic Auth 认证
- **Clash API** — 兼容 Clash API，可配合外部面板使用
- **单文件部署** — 静态编译，无 CGO 依赖，~21MB 开箱即用

## 快速开始

### 下载

从 [Releases](../../releases) 页面下载对应平台的预编译二进制文件：

```bash
# Linux amd64
wget -O warp-proxies https://github.com/lieyan/warp-proxies/releases/latest/download/warp-proxies-linux-amd64
chmod +x warp-proxies
```

### 从源码构建

```bash
git clone https://github.com/lieyan/warp-proxies.git
cd warp-proxies
make build           # 当前平台
make build-linux     # Linux amd64
make build-linux-arm64  # Linux arm64
```

> 需要 Go 1.23+，构建标签：`with_wireguard,with_gvisor,with_clash_api`

### 运行

```bash
./warp-proxies                  # 使用默认数据目录 ./data
./warp-proxies -data /etc/warp  # 指定数据目录
./warp-proxies -version         # 查看版本
```

首次启动会自动在数据目录下创建 `settings.json` 默认配置。

## 默认端口

| 服务 | 地址 | 说明 |
|------|------|------|
| SOCKS5 | `127.0.0.1:1080` | SOCKS5 代理 |
| HTTP | `127.0.0.1:8080` | HTTP/HTTPS 代理 |
| WebUI | `:9090` | 管理面板（admin/admin） |
| Clash API | `127.0.0.1:9097` | Clash 兼容 API |

## 配置

所有配置通过 WebUI 或 REST API 修改，持久化在 `data/settings.json`：

```json
{
  "proxy_host": "127.0.0.1",
  "socks_port": 1080,
  "http_port": 8080,
  "proxy_user": "",
  "proxy_pass": "",
  "web_addr": ":9090",
  "web_user": "admin",
  "web_pass": "admin",
  "rotation_mode": "urltest",
  "urltest_url": "https://www.gstatic.com/generate_204",
  "urltest_interval": 300,
  "urltest_tolerance": 50,
  "random_interval": 30,
  "clash_api_port": 9097,
  "clash_api_secret": ""
}
```

| 字段 | 说明 |
|------|------|
| `proxy_host` | 代理监听地址 |
| `socks_port` / `http_port` | 代理端口 |
| `proxy_user` / `proxy_pass` | 代理认证（留空则无认证） |
| `web_addr` / `web_user` / `web_pass` | WebUI 地址和 Basic Auth 凭据 |
| `rotation_mode` | 轮换模式：`urltest`（延迟最优）或 `random`（随机切换） |
| `urltest_*` | URLTest 相关参数（测试地址、间隔秒数、容差 ms） |
| `random_interval` | 随机轮换间隔（秒） |
| `clash_api_port` | Clash API 端口（设为 0 关闭） |

## API

所有 API 需 Basic Auth 认证（与 WebUI 相同）。

### 状态

```
GET /api/status
```

### 账户管理

```
GET    /api/accounts            # 列出所有账户
POST   /api/accounts            # 注册新账户  {"name":"", "endpoint":"", "endpoint_port":0}
POST   /api/accounts/batch      # 批量注册    {"count":5}
PATCH  /api/accounts/{id}       # 更新账户    {"name":"", "enabled":true, "endpoint":""}
DELETE /api/accounts/{id}       # 删除账户
```

### 设置

```
GET /api/settings               # 获取设置
PUT /api/settings               # 更新设置（完整替换）
```

### 引擎控制

```
POST /api/engine/restart        # 重启 sing-box 引擎
POST /api/engine/mode           # 切换轮换模式  {"mode":"urltest"}
```

## 架构

```
┌─────────────────────────────────────────┐
│                 Inbound                 │
│         SOCKS5(:1080)  HTTP(:8080)      │
└──────────────────┬──────────────────────┘
                   │
          ┌────────▼────────┐
          │  Selector(proxy) │  ← 手动选择 / 模式切换
          └────────┬────────┘
                   │
          ┌────────▼────────┐
          │  URLTest(auto)  │  ← 自动延迟测试
          └────────┬────────┘
                   │
     ┌─────────────┼─────────────┐
     ▼             ▼             ▼
 ┌────────┐  ┌────────┐   ┌────────┐
 │  WG-1  │  │  WG-2  │   │  WG-N  │  ← WireGuard/WARP 隧道
 └────────┘  └────────┘   └────────┘
```

## 项目结构

```
main.go                          入口：CLI 参数、信号处理
internal/
├── store/                       JSON 文件持久化
│   ├── store.go                 账户和设置的 CRUD
│   └── types.go                 Account / Settings 结构体
├── warp/                        Cloudflare WARP API 客户端
│   ├── client.go                注册 / 删除账户
│   ├── keygen.go                WireGuard 密钥对生成
│   └── types.go                 API 请求/响应结构体
├── engine/                      sing-box 引擎封装
│   ├── engine.go                生命周期管理（启动/停止/重启）
│   ├── config.go                sing-box 配置生成
│   └── rotation.go              出站轮换逻辑
└── web/                         HTTP 服务
    ├── handler.go               REST API 处理器
    ├── server.go                路由、Basic Auth、CORS
    └── static/index.html        嵌入式 SPA 前端
```

## License

[MIT](LICENSE)
