package com.network.analysis;

import com.network.model.IpPacket;
import com.network.model.TcpSegment;
import com.network.model.UdpDatagram;
import com.network.parser.ParseResult;

import java.util.*;
import java.util.stream.Collectors;

/**
 * 分析4: TCP/UDP端口分布直方图 + Top10端口长度CDF
 *
 * 分别对TCP和UDP流量:
 *   1. 统计端口出现的频次 (同时计入源端口和目的端口)
 *   2. 输出端口分布直方图
 *   3. 取前10名端口，绘制其IP数据报长度的CDF曲线进行对比
 */
public class PortHistogramAnalyzer {

    /** Top N 端口 */
    private static final int TOP_N = 10;

    /**
     * 单方向单协议的端口分析
     */
    public static class ProtocolPortResult {
        /** 端口 → 出现次数 */
        public final Map<Integer, Integer> portFrequency;
        /** Top10 端口列表 (按频次降序) */
        public final List<Map.Entry<Integer, Integer>> topPorts;
        /** Top10端口 → 该端口相关IP分组的长度列表 (已排序, 用于CDF) */
        public final Map<Integer, int[]> topPortLengths;

        public ProtocolPortResult(Map<Integer, Integer> freq,
                                  List<Map.Entry<Integer, Integer>> top,
                                  Map<Integer, int[]> lengths) {
            this.portFrequency = freq;
            this.topPorts = top;
            this.topPortLengths = lengths;
        }
    }

    /**
     * 完整分析结果
     */
    public static class Result {
        public final ProtocolPortResult tcpInbound;
        public final ProtocolPortResult tcpOutbound;
        public final ProtocolPortResult udpInbound;
        public final ProtocolPortResult udpOutbound;

        public Result(ProtocolPortResult tcpIn, ProtocolPortResult tcpOut,
                      ProtocolPortResult udpIn, ProtocolPortResult udpOut) {
            this.tcpInbound = tcpIn; this.tcpOutbound = tcpOut;
            this.udpInbound = udpIn; this.udpOutbound = udpOut;
        }
    }

    /**
     * 执行分析
     */
    public Result analyze(ParseResult parseResult) {
        return new Result(
                analyzeProtocolPorts(parseResult.getInbound(), "TCP"),
                analyzeProtocolPorts(parseResult.getOutbound(), "TCP"),
                analyzeProtocolPorts(parseResult.getInbound(), "UDP"),
                analyzeProtocolPorts(parseResult.getOutbound(), "UDP")
        );
    }

    /**
     * 对特定方向和协议的端口进行分析
     */
    private ProtocolPortResult analyzeProtocolPorts(List<IpPacket> packets, String protocol) {
        // 1. 统计端口频率 (srcPort 和 dstPort 都计入)
        Map<Integer, Integer> portFreq = new HashMap<>();

        // 2. 记录每个端口关联的IP分组长度
        Map<Integer, List<Integer>> portLengths = new HashMap<>();

        for (IpPacket p : packets) {
            if (!p.getProtocol().equals(protocol)) continue;

            int[] ports = getPorts(p, protocol);
            if (ports == null) continue;

            for (int port : ports) {
                portFreq.merge(port, 1, Integer::sum);
                portLengths.computeIfAbsent(port, k -> new ArrayList<>())
                        .add(p.getTotalLength());
            }
        }

        // 3. 按频次排序，取 Top N
        List<Map.Entry<Integer, Integer>> topPorts = portFreq.entrySet().stream()
                .sorted(Map.Entry.<Integer, Integer>comparingByValue().reversed())
                .limit(TOP_N)
                .collect(Collectors.toList());

        // 4. 为 Top N 端口准备排序的长度数组 (用于 CDF)
        Map<Integer, int[]> topLengths = new LinkedHashMap<>();
        for (Map.Entry<Integer, Integer> entry : topPorts) {
            int port = entry.getKey();
            List<Integer> lengths = portLengths.getOrDefault(port, Collections.emptyList());
            Collections.sort(lengths);
            topLengths.put(port, lengths.stream().mapToInt(Integer::intValue).toArray());
        }

        return new ProtocolPortResult(portFreq, topPorts, topLengths);
    }

    /**
     * 获取 IP 分组涉及的端口号 (源端口 + 目的端口, 去重)
     */
    private int[] getPorts(IpPacket p, String protocol) {
        if ("TCP".equals(protocol) && p.getTcpSegment() != null) {
            TcpSegment tcp = p.getTcpSegment();
            if (tcp.getSrcPort() == tcp.getDstPort()) {
                return new int[]{tcp.getSrcPort()};
            }
            return new int[]{tcp.getSrcPort(), tcp.getDstPort()};
        }
        if ("UDP".equals(protocol) && p.getUdpDatagram() != null) {
            UdpDatagram udp = p.getUdpDatagram();
            if (udp.getSrcPort() == udp.getDstPort()) {
                return new int[]{udp.getSrcPort()};
            }
            return new int[]{udp.getSrcPort(), udp.getDstPort()};
        }
        return null;
    }
}
