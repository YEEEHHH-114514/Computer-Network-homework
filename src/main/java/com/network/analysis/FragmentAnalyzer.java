package com.network.analysis;

import com.network.model.IpPacket;
import com.network.parser.ParseResult;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 分析2: IP分片统计
 *
 * 分别统计入站/出站:
 *   1. 有多少IP分组是片段 (fragment)
 *   2. 有多少IP数据报被分片 (按标识字段归组)
 *   3. TCP/UDP 载荷的IP数据报被分片的比例
 */
public class FragmentAnalyzer {

    /**
     * 单方向的分片统计
     */
    public static class DirectionResult {
        /** IP分组中片段(fragment)的数量 */
        public final int fragmentPacketCount;
        /** 被分片的IP数据报数量 (按 identification+src+dst+proto 归组) */
        public final int fragmentedDatagramCount;
        /** 该方向IP分组总数 */
        public final int totalPacketCount;
        /** TCP数据报被分片的比例 (0.0 ~ 1.0) */
        public final double tcpFragmentedRatio;
        /** UDP数据报被分片的比例 (0.0 ~ 1.0) */
        public final double udpFragmentedRatio;

        public DirectionResult(int fragPkts, int fragDatagrams, int total,
                               double tcpRatio, double udpRatio) {
            this.fragmentPacketCount   = fragPkts;
            this.fragmentedDatagramCount = fragDatagrams;
            this.totalPacketCount      = total;
            this.tcpFragmentedRatio    = tcpRatio;
            this.udpFragmentedRatio    = udpRatio;
        }
    }

    /**
     * 完整分析结果 (入站 + 出站)
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
        int total = packets.size();
        int fragmentPacketCount = 0;
        Set<String> fragmentGroups = new HashSet<>();       // 所有被分片的数据报
        Set<String> tcpFragmentGroups = new HashSet<>();    // TCP 被分片
        Set<String> udpFragmentGroups = new HashSet<>();    // UDP 被分片
        int tcpNonFragCount = 0;
        int udpNonFragCount = 0;

        for (IpPacket p : packets) {
            if (p.isFragment()) {
                fragmentPacketCount++;
                String key = datagramKey(p);
                fragmentGroups.add(key);

                if (p.isTcp()) {
                    tcpFragmentGroups.add(key);
                } else if (p.isUdp()) {
                    udpFragmentGroups.add(key);
                }
            } else {
                // 非分片包: 每个是一条完整的数据报
                if (p.isTcp()) {
                    tcpNonFragCount++;
                } else if (p.isUdp()) {
                    udpNonFragCount++;
                }
            }
        }

        int fragmentedDatagramCount = fragmentGroups.size();

        // TCP 被分片比例 = 被分片的TCP数据报 / 全部TCP数据报
        int totalTcpDatagrams = tcpNonFragCount + tcpFragmentGroups.size();
        double tcpRatio = totalTcpDatagrams > 0
                ? (double) tcpFragmentGroups.size() / totalTcpDatagrams
                : 0.0;

        // UDP 被分片比例
        int totalUdpDatagrams = udpNonFragCount + udpFragmentGroups.size();
        double udpRatio = totalUdpDatagrams > 0
                ? (double) udpFragmentGroups.size() / totalUdpDatagrams
                : 0.0;

        return new DirectionResult(fragmentPacketCount, fragmentedDatagramCount,
                total, tcpRatio, udpRatio);
    }

    /**
     * 生成数据报唯一标识: srcIp|dstIp|protocol|identification
     */
    private String datagramKey(IpPacket p) {
        return p.getSrcIp() + "|" + p.getDstIp() + "|"
                + p.getProtocol() + "|" + p.getIdentification();
    }
}
