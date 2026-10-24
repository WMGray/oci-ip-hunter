# Oracle Cloud (OCI) Python SDK & 黄金公网 IP 优选测速工具箱

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![OCI SDK](https://img.shields.io/badge/OCI%20SDK-Latest-orange.svg)](https://github.com/oracle/oci-python-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

基于官方 **Oracle Cloud Infrastructure (OCI) 纯 Python SDK** 构建的高性能云管底座与 IP 资产治理工具箱。

不仅提供计算、网络、存储的原生云管理能力，更独创了针对跨境公网的**黄金纯净 IP 批量猎取、借壳挂桩直连测速、TUN 代理物理穿透与生产主机一键换绑**全流程自动化闭环。

---

## 🌟 核心特性

- 🎯 **深度信誉与流媒体/AI 解锁体检 (`ip_quality.py`)**：
  - 静态情报交叉校验：Scamalytics（欺诈分）、IPPure（纯净度系数）、IP2Location、机房/原生广播判定、邮件黑名单（Spamhaus/FireHOL/IPsum）；
  - 全球主流流媒体及 AI 服务解锁检测：YouTube Premium、Netflix、Disney+、ChatGPT、Claude 等；
  - 智能综合评分体系：依据三大黄金指标自动打分与评级。
- ⚡ **无代理物理真实链路测速 (`windows_probe.ps1` + `oracle_ip_loop.py`)**：
  - **穿透代理机制**：自动识别本地物理路由器网关，下发内核级直连临时路由，**彻底绕过 Clash / Mihomo 等 TUN 虚拟网卡代理拦截**；
  - **借壳测试桩机制**：利用实例辅助私网 IP（`10.0.0.250`）动态 1:1 NAT 挂载闲置预留 IP，**测完即刻解绑复原**，绝不触碰生产主机主 IP；
  - **长效统计学压测**：支持 5~20 轮连续采样，精准计算真实平均往返时延（RTT）、网络抖动（Jitter）与实际丢包率并生成排行榜。
- 🎰 **5x5 批量平滑猎取 (`Hunt 模式`)**：
  - 支持配置严格门槛（如：欺诈分 < 5、IPPure ≤ 35%、流媒体 ≥ 4 项）；
  - 集成 `AntiBanGuard` 防封号守卫，带动态随机抖动（Jitter）安全休眠，达标自动重命名保留，劣质秒级释放。
- 🔄 **生产主机主公网 IP 一键换绑 (`Bind 模式`)**：
  - 自动识别实例主私网 IP（Primary Private IP）；
  - 自动清理原临时公网 IP（EPHEMERAL）或解绑旧预留公网 IP，将优选出的黄金 IP 一键无缝绑定上线。
- 🛡️ **双检联动闭环流水线 (`Pipeline 模式`)**：
  - 质量快筛门禁 + 物理链路延迟门禁联动，双优选方才锁定入库。
- ☁️ **原生 OCI SDK 纯净底座 (`src/`)**：
  - 100% 原生 SDK 与 HTTPS API 调用，**零外部 CLI 依赖**；
  - 模块化设计：`compute`（计算/规格/网卡）、`network`（VCN/子网/预留IP）、`storage`（对象存储/引导卷）。

---

## 📁 项目目录结构

```text
OracleCloud/
├── .gitignore              # Git 忽略配置（屏蔽环境、日志、临时报告与密钥）
├── pyproject.toml          # 现代化 Python 构建配置
├── requirements.txt        # pip 依赖清单
├── README.md               # 项目完整说明文档
│
├── src/                    # OCI 纯 Python SDK 核心模块
│   ├── __init__.py         # 导出 OCIClient, AuthManager
│   ├── auth.py             # 统一认证中心（API Key Signer / 浏览器 SSO 临时 Session）
│   ├── client.py           # 客户端统一门面入口 OCIClient
│   ├── compute.py          # 计算模块（实例查询、启停、重启、规格调整、网卡挂载）
│   ├── network.py          # 网络模块（VCN、子网、路由表、预留公网 IP、辅助私网 IP）
│   ├── storage.py          # 存储模块（块存储引导卷扩容/挂载、对象存储桶/对象读写）
│   └── cli.py              # 通用 OCI 资源运维命令行工具
│
└── tools/                  # 核心应用与自动化工具集
    ├── oracle_ip_loop.py   # ★ 核心全功能引擎（批量摇号 / 挂桩测速 / 生产换绑 / 双检流水线）
    ├── ip_quality.py       # ★ 静态 IP 纯净度体检与综合评分引擎（流媒体/欺诈分/IPPure）
    ├── windows_probe.ps1   # ★ Windows 内核级穿透代理测速脚本（临时物理网关直连）
    └── ips.example.txt     # 待测公网 IP 列表示例模版
```

---

## 🔑 认证与环境配置

本项目支持标准 OCI 凭据，使用前请确保本地已配置 `~/.oci/config`。

### 1. 配置 `~/.oci/config`（推荐使用 API Key）

在用户目录的 `.oci/config`（Windows 下为 `C:\Users\<用户名>\.oci\config`）中填入您的 OCI 凭据：

```ini
[DEFAULT]
user=ocid1.user.oc1..aaaaaaaaxxxxxxxxxxxxxxxxxxxxxxxxxxxx
fingerprint=20:3b:97:13:55:1c:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx
key_file=~/.oci/oci_api_key.pem
tenancy=ocid1.tenancy.oc1..aaaaaaaaxxxxxxxxxxxxxxxxxxxxxxxxxxxx
region=us-sanjose-1
```

> **提示**：若使用临时会话，也可通过浏览器 SSO 登录：
> ```powershell
> uv run python src/cli.py auth login --region us-sanjose-1
> ```

### 2. 安装依赖

推荐使用超快的 [`uv`](https://github.com/astral-sh/uv)：

```powershell
# 使用 uv 同步环境
uv sync

# 或使用传统 pip 安装
pip install -r requirements.txt
```

---

## 🚀 核心功能与使用指南

### 一、 挂测试桩无代理测速（测延迟 / 丢包 / 抖动排行榜）

利用常驻辅助私网 IP 借壳挂载预留 IP，穿透本地代理直连探测，测完立即解绑复原。

> **重要提示（Windows 环境）**：
> 由于需要调用 Windows 内核路由表注入临时直连物理路由以穿透 TUN 代理，**请在【以管理员身份运行】的 PowerShell 或 Terminal 中执行测速**。

```powershell
# 1. 对当前租户内所有已预留的公网 IP 逐一挂桩测速（默认 5 轮，并生成排行榜）
uv run python tools/oracle_ip_loop.py --mode latency --all

# 2. 深度高精度压测（每个 IP 连续采集 20 轮，共 40 个真实采样点，极力推荐！）
uv run python tools/oracle_ip_loop.py --mode latency --all --rounds 20 --ping-count 2

# 3. 交互式菜单选择测速（列出清单，输入序号测试指定 IP）
uv run python tools/oracle_ip_loop.py --mode latency

# 4. 指定某个具体的预留公网 IP 单独挂桩测速
uv run python tools/oracle_ip_loop.py --mode latency --ip 129.146.0.1 --rounds 10
```

---

### 二、 生产主机主公网 IP 一键换绑上线 (`Bind 模式`)

自动置换 `oci-main-arm` 主网卡上的旧 IP（自动删除临时 IP 或解绑旧预留 IP），将测速优胜的黄金 IP 绑定上线为 Primary Public IP。

```powershell
# 1. 一键将指定的黄金预留 IP 绑定为云主机的主公网 IP
uv run python tools/oracle_ip_loop.py --mode bind --ip 129.146.0.1

# 2. 交互式选择换绑（列出所有预留 IP 供选择绑定）
uv run python tools/oracle_ip_loop.py --mode bind
```

---

### 三、 批量优选摇号猎取黄金 IP (`Hunt 模式`)

批量申请预留 IP -> 快速质量体检 -> 达标自动重命名（`vip-pure-sjc-xx`）保留 -> 未达标秒级释放退回 -> 防封随机抖动休眠。

```powershell
# 1. 极速模式批量优选摇号（跳过无头浏览器，秒级快筛，默认目标保留 5 个黄金 IP）
uv run python tools/oracle_ip_loop.py --hunt --fast

# 2. 自定义门槛摇号（要求欺诈分 < 5，IPPure ≤ 30%，流媒体解锁 ≥ 5 项）
uv run python tools/oracle_ip_loop.py --hunt --fast --max-scam 5 --max-ippure 30.0 --min-streaming 5
```

---

### 四、 纯静态质量与信誉体检 (`ip_quality.py`)

不触碰任何云主机，纯静态分析任意公网 IP 的风险画像与解锁情况。

```powershell
# 1. 单 IP 快速风控体检（彩色控制台仪表盘）
uv run python tools/ip_quality.py 129.146.0.1

# 2. 输出标准结构化 JSON 数据（便于二次集成）
uv run python tools/ip_quality.py 129.146.0.1 --json

# 3. 批量读取文件中的 IP 列表进行体检对比并打分
uv run python tools/ip_quality.py --file tools/ips.example.txt
```

---

### 五、 纯净度 + 物理延迟双门禁联动流水线 (`Pipeline 模式`)

摇出纯净度达标 IP 后自动触发挂桩测速，物理延迟与纯净度双合格才保留，否则自动释放：

```powershell
uv run python tools/oracle_ip_loop.py --mode pipeline --fast --max-rtt 230.0
```

---

### 六、 OCI 云资源基础管理命令 (`src/cli.py`)

```powershell
# 1. 验证认证有效性
uv run python src/cli.py auth status --online

# 2. 查询实例清单与状态
uv run python src/cli.py compute list

# 3. 查看当前租户所有可用实例规格 (Shapes)
uv run python src/cli.py compute shapes

# 4. 重启指定实例
uv run python src/cli.py compute restart --instance-id <INSTANCE_OCID>

# 5. 查询虚拟云网络 (VCN) 与子网
uv run python src/cli.py network vcns
uv run python src/cli.py network subnets

# 6. 查询预留公网 IP（闲置 / 已绑定状态反查）
uv run python src/cli.py public-ip --type all
```

---

## 🛠️ 云主机测试桩配置说明

为了实现**无损借壳挂载测速**（不影响主机生产主 IP），本工具会在实例主网卡上自动关联一个辅助私网 IP（默认 `10.0.0.250`）。

若您使用的是全新初始化的 Ubuntu / Debian 实例，仅需在实例中执行一次以下命令让操作系统识别辅助私网 IP 即可：

```bash
# 确认您的网卡名称（通常为 enp0s6 或 ens3）
ip addr

# 为网卡添加辅助测试桩私网 IP
sudo ip addr add 10.0.0.250/24 dev enp0s6
```

---

## 📄 开源许可

本项目遵循 [MIT License](LICENSE) 许可协议。
欢迎提交 Issue 与 Pull Request 共同完善！
