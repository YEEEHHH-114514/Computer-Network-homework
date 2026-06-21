package com.network.analysis;

import com.network.model.IpPacket;
import com.network.model.TcpSegment;
import com.network.parser.ParseResult;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 分析5: TCP控制位出现百分比统计
 *
 * 分别对入站/出站TCP流量，统计各控制位:
 *   SYN, ACK, FIN, RST, PSH, URG
 * 在TCP段中置位的百分比。
 */
public class TcpControlBitsAnalyzer {

    private static final String[] FLAGS = {"SYN", "ACK", "FIN", "RST", "PSH", "URG"};

    /**
     * 单方向的控制位统计
     */
    public static class DirectionResult {
        /** TCP 分组总数 */
        public final int tcpPacketCount;
        /** 标志位 → 出现百分比 (0.0 ~ 100.0) */
        public final Map<String, Double> flagPercentages;

        public DirectionResult(int count, Map<String, Double> percentages) {
            this.tcpPacketCount = count;
            this.flagPercentages = percentages;
        }
    }

    /**
     * 完整分析结果
     */
    public static class Result {
        public final DirectionResult inbound;
        public final DirectionResult outbound;

        public Result(DirectionResult in, DirectionResult out) {
            this.inbound = in; this.outbound = out;
        }
    }

    /**
     * 执行分析
     */
    public Result analyze(ParseResult parseResult) {
        return new Result(
                analyzeDirection(parseResult.getInbound()),
                analyzeDirection(parseResult.getOutbound())
        );
    }

    private DirectionResult analyzeDirection(List<IpPacket> packets) {
        int[] counts = new int[FLAGS.length]; // SYN, ACK, FIN, RST, PSH, URG
        int tcpCount = 0;

        for (IpPacket p : packets) {
            if (!p.isTcp()) continue;
            TcpSegment tcp = p.getTcpSegment();
            if (tcp == null) continue;

            tcpCount++;
            if (tcp.isSyn()) counts[0]++;
            if (tcp.isAck()) counts[1]++;
            if (tcp.isFin()) counts[2]++;
            if (tcp.isRst()) counts[3]++;
            if (tcp.isPsh()) counts[4]++;
            if (tcp.isUrg()) counts[5]++;
        }

        Map<String, Double> percentages = new LinkedHashMap<>();
        for (int i = 0; i < FLAGS.length; i++) {
            double pct = tcpCount > 0 ? (counts[i] * 100.0 / tcpCount) : 0.0;
            percentages.put(FLAGS[i], pct);
        }

        return new DirectionResult(tcpCount, percentages);
    }
}
