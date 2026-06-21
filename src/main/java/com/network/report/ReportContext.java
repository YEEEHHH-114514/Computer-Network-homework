package com.network.report;

import com.network.analysis.FragmentAnalyzer;
import com.network.analysis.PortHistogramAnalyzer;

import java.util.Map;

/**
 * 报告上下文 — 聚合全部分析结果与图表路径
 *
 * 由 Main 在完成所有分析 + 图表生成后填充，
 * 然后传给 HtmlGenerator 生成 report.html。
 */
public class ReportContext {

    // ======== 元数据 ========
    public String localIp;
    public String sourceFile;
    public int totalPackets;

    // ======== 分析1: 协议分布 ========
    public Map<String, Integer> protoInCounts, protoOutCounts;
    public Map<String, Long>    protoInVolumes, protoOutVolumes;
    public String chartProtoInCount, chartProtoInVolume;
    public String chartProtoOutCount, chartProtoOutVolume;

    // ======== 分析2: 分片统计 ========
    public FragmentAnalyzer.DirectionResult fragIn, fragOut;

    // ======== 分析3: 长度 CDF ========
    public String chartCdfIn, chartCdfOut;

    // ======== 分析4: 端口分布 ========
    public PortHistogramAnalyzer.ProtocolPortResult portTcpIn, portTcpOut;
    public PortHistogramAnalyzer.ProtocolPortResult portUdpIn, portUdpOut;
    public String chartTcpInHist, chartTcpOutHist, chartUdpInHist, chartUdpOutHist;
    public String chartTcpInCdf,  chartTcpOutCdf,  chartUdpInCdf,  chartUdpOutCdf;

    // ======== 分析5: TCP 控制位 ========
    public Map<String, Double> tcpFlagsIn, tcpFlagsOut;
    public int tcpInCount, tcpOutCount;
    public String chartTcpFlags;

    // ======== 分析6: HTTP 会话 ========
    public String httpSessionTable;  // HTML 表格片段，null 表示未实现
}
