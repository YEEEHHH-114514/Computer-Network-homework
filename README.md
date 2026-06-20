# 计算机网络课程大作业

基于 Java 的网络流量采集、分析与可视化工具。

## 项目结构

```
├── captures/           # Wireshark 抓包文件存放目录
├── src/main/java/com/network/
│   ├── Main.java              # 程序入口
│   ├── parser/                # PCAP 文件解析
│   ├── model/                 # 数据模型
│   ├── analysis/              # 统计分析模块
│   ├── http/                  # HTTP 会话提取 (第5题)
│   └── report/                # 图表生成 & HTML 输出
├── output/                    # 程序输出
│   ├── charts/                # 图表 PNG
│   └── report.html            # 结果展示页
└── pom.xml                    # Maven 配置
```

## 技术栈

- **语言**: Java 21
- **构建**: Maven
- **PCAP 解析**: Pcap4J
- **图表生成**: JFreeChart
- **前端展示**: 静态 HTML (output/report.html)

## 分析功能

1. IP 协议载荷分布 (饼图: 分组数 & 数据量)
2. IP 分片统计
3. IP 数据报长度累积分布 (CDF)
4. TCP/UDP 端口分布直方图 & Top10 端口 CDF
5. TCP 控制位百分比
6. HTTP 会话 TCP 拆解分析

## 使用方式

```bash
# 1. 将 Wireshark 抓包文件放入 captures/ 目录

# 2. 用 Maven 编译运行
mvn clean compile exec:java -Dexec.mainClass="com.network.Main"

# 3. 打开 output/report.html 查看结果
```
