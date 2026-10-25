# oci-ip-hunter

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![OCI SDK](https://img.shields.io/badge/OCI%20SDK-Latest-orange.svg)](https://github.com/oracle/oci-python-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Oracle Cloud Infrastructure (OCI) 预留公网 IP 管理与测试工具。提供预留公网 IP 的批量申请与筛选、本地直连链路时延测量，以及计算实例公网 IP 的绑定管理。

---

## 主要功能

- **批量申请与筛选 (`Hunt`)**：批量申请预留公网 IP，结合风控评分（Scamalytics）、纯净度（IPPure）以及常见流媒体/AI 连通性进行检测。保留符合条件的 IP，释放不符合条件的 IP。
- **直连链路测速 (`Latency`)**：在 Windows 环境下通过添加临时主机路由，使 ICMP 报文绕过 TUN 虚拟网卡直达本地网关，用于测量实际的网络往返时延（RTT）、网络抖动与丢包率。
- **辅助私网 IP 测试桩**：通过将待测公网 IP 临时绑定至计算实例的辅助私网 IP（Secondary Private IP）进行连通性测试，测试完毕后自动解绑，不修改实例的原有公网 IP。
- **实例主公网 IP 绑定 (`Bind`)**：将指定的预留公网 IP 关联至生产计算实例的主私网 IP，替换原有的临时公网 IP 或旧预留 IP。
- **独立 IP 质量分析 (`ip_quality.py`)**：不依赖 OCI 云上环境，可直接对指定公网 IP 进行风控分值、原生机房属性、25 端口出站状态及服务连通性分析。

---

## 工作模式

| 模式 (`--mode`) | 检测内容 | 依赖云主机 | 预期耗时 | 说明 |
| :--- | :--- | :---: | :---: | :--- |
| **`quality` (完整模式)** | 欺诈分、IPPure (调用无头浏览器)、流媒体与 AI、邮件端口、黑名单 | 否 | 约 10~15 秒 / IP | 获取包含人机流量比的完整检测报告。 |
| **`quality` (快速模式, `--fast`)** | 欺诈分、流媒体与 AI、邮件端口、黑名单 (跳过 IPPure) | 否 | 约 2~3 秒 / IP | 批量申请时的常规模式，缩短等待时间。 |
| **`latency`** | ICMP 往返时延 (RTT)、抖动 (Jitter)、丢包率 | 是 (挂载至辅助私网 IP) | 取决于测试轮数 (约 5~20 秒 / IP) | 测量本地到云主机的实际直连网络质量。 |
| **`pipeline`** | 先执行质量筛选，达标后自动进行链路测速 | 是 | 动态耗时 | 仅当 IP 同时满足质量要求与时延阈值时才予以保留。 |
| **`bind`** | 执行公网 IP 关联操作 | 是 | 约 2 秒 | 将指定的预留 IP 绑定为云主机的主公网 IP。 |

---

## 运行环境与安装

### 前提条件
- Python 3.10 或更高版本
- 已配置 OCI API 密钥凭据（见下文）
- Windows 环境下运行链路测速需要管理员权限（用于临时修改系统路由表）

### 安装依赖

使用 [`uv`](https://github.com/astral-sh/uv)：

```bash
git clone https://github.com/WMGray/oci-ip-hunter.git
cd oci-ip-hunter

# 创建并同步虚拟环境
uv sync

# 或使用 pip
pip install -r requirements.txt
```

---

## 凭据配置

在本地 `~/.oci/config`（Windows 路径为 `C:\Users\<USER>\.oci\config`）中配置 OCI 凭据：

```ini
[DEFAULT]
user=ocid1.user.oc1..aaaaaaaaxxxxxxxxxxxxxxxxxxxxxxxxxxxx
fingerprint=20:3b:97:13:55:1c:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx
key_file=~/.oci/oci_api_key.pem
tenancy=ocid1.tenancy.oc1..aaaaaaaaxxxxxxxxxxxxxxxxxxxxxxxxxxxx
region=<YOUR_REGION>
```

> 注：请将 `<YOUR_REGION>` 替换为实际所在的 OCI 区域代码（如 `us-ashburn-1`、`ap-tokyo-1` 等）。

---

## 命令行参数说明

### 1. 全局参数

| 参数 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `--mode` | `quality` | 运行模式：`quality` (质量筛选), `latency` (链路测速), `pipeline` (流水线), `bind` (换绑主 IP) |
| `--profile` | `DEFAULT` | 配置文件中的 Profile 名称 |
| `--region` | 自动获取 | 覆盖配置文件中的区域代码 |

### 2. 质量筛选参数 (`--mode quality`)

| 参数 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `--hunt` | `False` | 启用批量循环申请与筛选 |
| `--fast` | `False` | 快速模式，跳过需要浏览器渲染的 IPPure 检测 |
| `--batch-size` | `5` | 每批申请的 IP 数量 |
| `--target-count`| `5` | 目标保留的达标 IP 数量 |
| `--max-batches` | `10` | 批量循环的最大轮数 |
| `--max-scam` | `5` | 允许的最大欺诈分值 (必须小于此值) |
| `--max-ippure` | `35.0` | 允许的最大 IPPure 风险系数 (百分比，`--fast` 下免检) |
| `--min-streaming`| `4` | 允许的最小解锁服务数量 (总共 7 项) |
| `--naming-prefix`| `vip-pure` | 达标 IP 在 OCI 中的命名规则前缀 (如 `vip-pure-01`) |
| `--cooldown` | `4.0` | 批次间隔的休眠等待时间 (秒) |
| `--allocate` | `False` | 单次模式下申请并测试一个新分配的预留 IP |
| `--auto` | `False` | 单次模式下根据结果自动保留或释放，不进行人工交互确认 |
| `--release` | `False` | 测试完成后直接释放该 IP，不保留 |
| `--timeout` | `15.0` | 各接口请求的超时时间 (秒) |

### 3. 链路测速参数 (`--mode latency`)

| 参数 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `--all` | `False` | 测试租户内所有现存的预留公网 IP 并输出统计表格 |
| `--ip` | 空 | 指定测试单个预留公网 IP |
| `--rounds` | `5` | 重复测试轮数，用于统计平均 RTT 与抖动 |
| `--ping-count` | `4` | 每轮发送的 ICMP 数据包数量 |
| `--gateway` | 自动探测 | 本地物理网关 IP，用于添加临时直连路由 |
| `--instance` | `oci-main-arm` | 测试桩所依托的计算实例名称 |

### 4. 流水线参数 (`--mode pipeline`)

| 参数 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `--max-rtt` | `220.0` | 允许的最大平均延迟阈值 (毫秒)，超过该阈值的 IP 将被释放 |

---

## 常用示例

### 1. 批量申请并筛选公网 IP
```bash
uv run python tools/oracle_ip_loop.py --hunt --fast
```

### 2. 自定义指标筛选
```bash
uv run python tools/oracle_ip_loop.py --hunt --fast --max-scam 3 --min-streaming 5
```

### 3. 测试现有预留 IP 的直连时延
```bash
# 测试指定实例下的所有预留 IP
uv run python tools/oracle_ip_loop.py --mode latency --all --instance <INSTANCE_NAME>

# 增加轮数进行采样 (20 轮)
uv run python tools/oracle_ip_loop.py --mode latency --all --rounds 20 --instance <INSTANCE_NAME>
```

### 4. 质量与时延联动筛选
```bash
uv run python tools/oracle_ip_loop.py --mode pipeline --fast --max-rtt 220.0 --instance <INSTANCE_NAME>
```

### 5. 为实例绑定公网 IP
```bash
uv run python tools/oracle_ip_loop.py --mode bind --ip <PUBLIC_IP> --instance <INSTANCE_NAME>
```

### 6. 独立分析任意单个公网 IP
```bash
uv run python tools/ip_quality.py 1.1.1.1
```

---

## 辅助私网 IP 配置说明

为避免测速影响实例当前正常的公网通信，测速功能依托实例网卡上的辅助私网 IP（默认预设为 `10.0.0.250`）。工具在测速时将待测公网 IP 临时绑定至该私网 IP，测完立即解绑。

首次使用前，需在 Linux 实例内执行一次网络别名配置：

```bash
# 查看主网卡接口名称 (通常为 enp0s6 或 ens3)
ip addr

# 添加辅助私网 IP (仅需执行一次)
sudo ip addr add 10.0.0.250/24 dev enp0s6
```

---

## 许可证

本项目基于 [MIT License](LICENSE) 许可发布。
