package com.network.analysis;

import com.network.model.IpPacket;
import com.network.parser.ParseResult;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 分析1: IP分组携带不同协议载荷的饼图
 *
 * 分别对入站/出站方向统计:
 *   - 按分组数: 各协议(TCP/UDP/ICMP/OTHER)的包数占比
 *   - 按总数据量: 各协议携带的载荷字节数占比
 */
public class ProtocolPieAnalyzer {

    /** 协议顺序 (保证饼图图例一致) */
    private static final String[] PROTOCOLS = {"TCP", "UDP", "ICMP", "OTHER"};

    /**
     * 分析结果
     */
    public static class Result {
        /** 入站 — 各组协议的分组数 */
        public final Map<String, Integer> inboundCounts;
        /** 入站 — 各协议的总数据量(字节) */
        public final Map<String, Long>    inboundVolumes;
        /** 出站 — 各协议的分组数 */
        public final Map<String, Integer> outboundCounts;
        /** 出站 — 各协议的总数据量(字节) */
        public final Map<String, Long>    outboundVolumes;

        public Result(Map<String, Integer> inC, Map<String, Long> inV,
                      Map<String, Integer> outC, Map<String, Long> outV) {
            this.inboundCounts  = inC;
            this.inboundVolumes = inV;
            this.outboundCounts = outC;
            this.outboundVolumes = outV;
        }

        public int totalInboundCount() {
            return inboundCounts.values().stream().mapToInt(Integer::intValue).sum();
        }

        public int totalOutboundCount() {
            return outboundCounts.values().stream().mapToInt(Integer::intValue).sum();
        }
    }

    /**
     * 执行分析
     */
    public Result analyze(ParseResult parseResult) {
        Map<String, Integer> inC  = analyzeCounts(parseResult.getInbound());
        Map<String, Long>    inV  = analyzeVolumes(parseResult.getInbound());
        Map<String, Integer> outC = analyzeCounts(parseResult.getOutbound());
        Map<String, Long>    outV = analyzeVolumes(parseResult.getOutbound());
        return new Result(inC, inV, outC, outV);
    }

    private Map<String, Integer> analyzeCounts(List<IpPacket> packets) {
        Map<String, Integer> counts = initProtocolMap(0);
        for (IpPacket p : packets) {
            String proto = p.getProtocol();
            counts.merge(proto, 1, Integer::sum);
        }
        return counts;
    }

    private Map<String, Long> analyzeVolumes(List<IpPacket> packets) {
        Map<String, Long> volumes = initProtocolMap(0L);
        for (IpPacket p : packets) {
            String proto = p.getProtocol();
            volumes.merge(proto, (long) p.getTotalLength(), Long::sum);
        }
        return volumes;
    }

    private <T> Map<String, T> initProtocolMap(T defaultValue) {
        Map<String, T> map = new LinkedHashMap<>();
        for (String proto : PROTOCOLS) {
            map.put(proto, defaultValue);
        }
        return map;
    }
}
