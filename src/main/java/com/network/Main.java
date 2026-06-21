package com.network;

import com.network.analysis.*;
import com.network.http.HttpSessionExtractor;
import com.network.parser.ParseResult;
import com.network.parser.PcapParser;
import com.network.report.ChartGenerator;
import com.network.report.HtmlGenerator;
import com.network.report.ReportContext;

import java.io.IOException;
import java.util.Map;

/**
 * 计算机网络课程大作业 — 程序入口
 *
 * 完整流水线: 解析PCAP → 五类分析 → 生成图表 → 输出HTML报告
 *
 * 用法: java -jar ... <pcap文件路径> <本机IP>
 * 示例: java -jar ... captures/capture.pcapng 192.168.1.100
 */
public class Main {

    public static void main(String[] args) {
        // 解析参数
        if (args.length < 2) {
            System.out.println("用法: java -jar computer-network-homework.jar <pcap文件路径> <本机IP>");
            System.out.println("示例: java -jar ... captures/capture.pcapng 192.168.1.100");
            System.exit(1);
        }
        String pcapFile = args[0];
        String localIp  = args[1];

        try {
            new Main().run(pcapFile, localIp);
        } catch (Exception e) {
            System.err.println("运行失败: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    public void run(String pcapFile, String localIp) throws Exception {
        System.out.println("========================================");
        System.out.println("  计算机网络课程大作业 - 流量分析工具");
        System.out.println("========================================");
        System.out.println("PCAP 文件: " + pcapFile);
        System.out.println("本机 IP:   " + localIp);
        System.out.println();

        // ---------- Step 1: 解析 ----------
        System.out.println("[1/4] 解析 PCAP 文件...");
        PcapParser parser = new PcapParser(localIp);
        ParseResult parseResult = parser.parse(pcapFile);
        System.out.println("  -> " + parseResult);
        System.out.println("  入站: " + parseResult.getInbound().size()
                + " | 出站: " + parseResult.getOutbound().size()
                + " | 总计: " + parseResult.getTotalIpPackets());

        // ---------- Step 2: 分析 ----------
        System.out.println("[2/4] 执行五类分析...");

        ProtocolPieAnalyzer pieAnalyzer = new ProtocolPieAnalyzer();
        ProtocolPieAnalyzer.Result pieResult = pieAnalyzer.analyze(parseResult);
        System.out.println("  ✓ 协议分布");

        FragmentAnalyzer fragAnalyzer = new FragmentAnalyzer();
        FragmentAnalyzer.Result fragResult = fragAnalyzer.analyze(parseResult);
        System.out.println("  ✓ IP分片统计");

        LengthCdfAnalyzer cdfAnalyzer = new LengthCdfAnalyzer();
        LengthCdfAnalyzer.Result cdfResult = cdfAnalyzer.analyze(parseResult);
        System.out.println("  ✓ 长度CDF");

        PortHistogramAnalyzer portAnalyzer = new PortHistogramAnalyzer();
        PortHistogramAnalyzer.Result portResult = portAnalyzer.analyze(parseResult);
        System.out.println("  ✓ 端口分布");

        TcpControlBitsAnalyzer flagsAnalyzer = new TcpControlBitsAnalyzer();
        TcpControlBitsAnalyzer.Result flagsResult = flagsAnalyzer.analyze(parseResult);
        System.out.println("  ✓ TCP控制位");

        HttpSessionExtractor httpExtractor = new HttpSessionExtractor();
        HttpSessionExtractor.HttpSession httpSession = httpExtractor.extract(parseResult);
        if (httpSession != null) {
            System.out.println("  ✓ HTTP会话: " + httpSession.summary);
        } else {
            System.out.println("  ⚠ 未找到 HTTP 会话 (port 80)");
        }

        // ---------- Step 3: 生成图表 ----------
        System.out.println("[3/4] 生成图表 PNG...");
        ChartGenerator charts = new ChartGenerator("output/charts");

        ReportContext ctx = new ReportContext();
        ctx.localIp = localIp;
        ctx.sourceFile = pcapFile;
        ctx.totalPackets = parseResult.getTotalIpPackets();

        // -- 协议饼图 --
        ctx.protoInCounts  = pieResult.inboundCounts;
        ctx.protoInVolumes = pieResult.inboundVolumes;
        ctx.protoOutCounts  = pieResult.outboundCounts;
        ctx.protoOutVolumes = pieResult.outboundVolumes;

        ctx.chartProtoInCount  = "proto_inbound_count.png";
        ctx.chartProtoInVolume = "proto_inbound_volume.png";
        ctx.chartProtoOutCount  = "proto_outbound_count.png";
        ctx.chartProtoOutVolume = "proto_outbound_volume.png";

        charts.generateProtocolPie(ctx.protoInCounts,
                "入站 - 协议分布(按分组数)", ctx.chartProtoInCount);
        charts.generateProtocolPie(ctx.protoInVolumes,
                "入站 - 协议分布(按数据量)", ctx.chartProtoInVolume);
        charts.generateProtocolPie(ctx.protoOutCounts,
                "出站 - 协议分布(按分组数)", ctx.chartProtoOutCount);
        charts.generateProtocolPie(ctx.protoOutVolumes,
                "出站 - 协议分布(按数据量)", ctx.chartProtoOutVolume);

        // -- 分片统计 --
        ctx.fragIn  = fragResult.inbound;
        ctx.fragOut = fragResult.outbound;

        // -- 长度 CDF --
        ctx.chartCdfIn  = "cdf_inbound.png";
        ctx.chartCdfOut = "cdf_outbound.png";
        charts.generateCdfChart(
                Map.of("全部IP", cdfResult.inbound.allLengths,
                       "TCP",    cdfResult.inbound.tcpLengths,
                       "UDP",    cdfResult.inbound.udpLengths),
                "入站 - IP数据报长度CDF", "长度(字节)", ctx.chartCdfIn);
        charts.generateCdfChart(
                Map.of("全部IP", cdfResult.outbound.allLengths,
                       "TCP",    cdfResult.outbound.tcpLengths,
                       "UDP",    cdfResult.outbound.udpLengths),
                "出站 - IP数据报长度CDF", "长度(字节)", ctx.chartCdfOut);

        // -- 端口直方图 + Top10 CDF --
        ctx.portTcpIn  = portResult.tcpInbound;
        ctx.portTcpOut = portResult.tcpOutbound;
        ctx.portUdpIn  = portResult.udpInbound;
        ctx.portUdpOut = portResult.udpOutbound;

        ctx.chartTcpInHist  = "tcp_inbound_ports.png";
        ctx.chartTcpOutHist = "tcp_outbound_ports.png";
        ctx.chartUdpInHist  = "udp_inbound_ports.png";
        ctx.chartUdpOutHist = "udp_outbound_ports.png";
        charts.generatePortHistogram(portResult.tcpInbound.topPorts,
                "TCP 入站 - Top10 端口分布", ctx.chartTcpInHist);
        charts.generatePortHistogram(portResult.tcpOutbound.topPorts,
                "TCP 出站 - Top10 端口分布", ctx.chartTcpOutHist);
        charts.generatePortHistogram(portResult.udpInbound.topPorts,
                "UDP 入站 - Top10 端口分布", ctx.chartUdpInHist);
        charts.generatePortHistogram(portResult.udpOutbound.topPorts,
                "UDP 出站 - Top10 端口分布", ctx.chartUdpOutHist);

        // Top10 CDF
        ctx.chartTcpInCdf  = generateTopPortCdf(charts, portResult.tcpInbound,  "TCP入站");
        ctx.chartTcpOutCdf = generateTopPortCdf(charts, portResult.tcpOutbound, "TCP出站");
        ctx.chartUdpInCdf  = generateTopPortCdf(charts, portResult.udpInbound,  "UDP入站");
        ctx.chartUdpOutCdf = generateTopPortCdf(charts, portResult.udpOutbound, "UDP出站");

        // -- TCP 控制位 --
        ctx.tcpFlagsIn  = flagsResult.inbound.flagPercentages;
        ctx.tcpFlagsOut = flagsResult.outbound.flagPercentages;
        ctx.tcpInCount  = flagsResult.inbound.tcpPacketCount;
        ctx.tcpOutCount = flagsResult.outbound.tcpPacketCount;
        ctx.chartTcpFlags = "tcp_flags.png";
        charts.generateTcpFlagsChart(ctx.tcpFlagsIn, ctx.tcpFlagsOut, ctx.chartTcpFlags);

        System.out.println("  ✓ 共生成 " + countCharts("output/charts") + " 张图表");

        // 生成 HTTP 会话 HTML 表格
        ctx.httpSessionTable = httpExtractor.toHtmlTable(httpSession);

        // ---------- Step 4: 生成 HTML ----------
        System.out.println("[4/4] 生成 HTML 报告...");
        HtmlGenerator html = new HtmlGenerator("output/report.html");
        html.generate(ctx);
        System.out.println("  ✓ output/report.html");

        System.out.println();
        System.out.println("========================================");
        System.out.println("  完成! 浏览器打开 output/report.html");
        System.out.println("========================================");
    }

    /**
     * 为 Top N 端口生成长度 CDF 对比图
     */
    private String generateTopPortCdf(ChartGenerator charts,
                                      PortHistogramAnalyzer.ProtocolPortResult result,
                                      String label) throws IOException {
        if (result.topPortLengths.isEmpty()) return null;

        String filename = (label.replaceAll(" ", "_") + "_top10_cdf.png").toLowerCase();
        Map<String, int[]> seriesMap = new java.util.LinkedHashMap<>();
        for (Map.Entry<Integer, int[]> e : result.topPortLengths.entrySet()) {
            seriesMap.put("端口 " + e.getKey(), e.getValue());
        }
        charts.generateCdfChart(seriesMap,
                label + " - Top10端口数据报长度CDF", "长度(字节)", filename);
        return filename;
    }

    private int countCharts(String dir) {
        java.io.File d = new java.io.File(dir);
        String[] pngs = d.list((f, n) -> n.endsWith(".png"));
        return pngs != null ? pngs.length : 0;
    }
}
