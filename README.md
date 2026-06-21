# 计算机网络课程大作业

基于 Java 的网络流量采集、分析与可视化工具。

## 项目结构

```
├── captures/                  # Wireshark 抓包文件存放目录
├── src/main/java/com/network/
│   ├── Main.java              # 程序入口
│   ├── parser/                # PCAP 文件解析 (PcapParser, ParseResult)
│   ├── model/                 # 数据模型 (IpPacket, TcpSegment, UdpDatagram)
│   ├── analysis/              # 5 类统计分析模块
│   ├── http/                  # HTTP 会话 TCP 拆解 (第5题)
│   └── report/                # 图表生成 (ChartGenerator) & HTML 输出 (HtmlGenerator)
├── output/                    # 程序输出 (自动生成)
│   ├── charts/                # 图表 PNG (~15 张)
│   └── report.html            # 结果展示页
├── run.bat                    # 一键运行脚本 (Windows)
└── pom.xml                    # Maven 配置
```

## 技术栈

| 组件 | 技术 |
|------|------|
| 语言 | Java 21 |
| 构建 | Maven |
| PCAP 解析 | Pcap4J 1.8.2 |
| 图表生成 | JFreeChart 1.5.4 |
| 日志 | SLF4J-nop 2.0.9 |
| 前端 | 静态 HTML (output/report.html) |

## 环境要求

- **JDK 21** — 编译和运行
- **Maven 3.9+** — 依赖管理 & 构建
- **Npcap** — Pcap4J 底层依赖，随 Wireshark 安装或从 [npcap.com](https://npcap.com) 单独下载
- **Wireshark** — 抓包（也可用 tcpdump 等其他工具）

## 分析功能

| # | 模块 | 输出 |
|---|------|------|
| ① | IP 协议载荷分布 | 入站/出站饼图 × 分组数 + 数据量 (4 张) |
| ② | IP 分片统计 | 分片包数、被分片数据报数、TCP/UDP 分片比例 |
| ③ | IP 数据报长度 CDF | 全部IP / TCP / UDP 三线累积分布曲线 |
| ④ | TCP/UDP 端口分布 | Top10 端口直方图 + 长度 CDF (8 张图) |
| ⑤ | TCP 控制位百分比 | SYN/ACK/FIN/RST/PSH/URG 柱状图 |
| ⑥ | HTTP 会话 TCP 拆解 | 三次握手 → 数据传输 → 四次挥手 逐包表格 |

## 快速开始

### Step 1: 抓包

1. 打开 **Wireshark**，选择上网网卡
2. Filter 栏输入 `host <你的IP>`（如 `host 192.168.1.100`）
3. 开始抓包后，浏览器访问 **http://example.com**（注意是 HTTP）
4. 页面加载完后停止抓包，`File → Save As` 保存为 `.pcapng`
5. 将文件放入 `captures/` 目录

### Step 2: 运行

双击 **`run.bat`**，按提示输入本机 IP 地址即可。

或手动命令行：

```bash
# 编译
mvn clean compile

# 运行
mvn exec:java -Dexec.mainClass="com.network.Main" -Dexec.args="captures/capture.pcapng 你的IP"

# 查看结果
start output/report.html
```

### Step 3: 查看

浏览器打开 `output/report.html`，6 个章节涵盖全部分析结果，图表和数据表格方便直接截图到实验报告。

## 注意事项

- 必须用 **HTTP**（port 80）访问测试网站，HTTPS 加密后第⑥题无法提取明文会话
- Wireshark filter 务必用 `host <IP>` 限定本机流量，避免混杂无关设备
- 抓包时长 ~1 分钟，产生几百到几千个分组即可满足分析需求
- 如遇 `Unable to load library 'wpcap'` 错误，需安装 Npcap 并勾选 WinPcap API-compatible Mode
