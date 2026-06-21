package com.network.analysis;

import com.network.model.IpPacket;
import com.network.parser.ParseResult;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 分析3: IP数据报长度累积分布曲线 (CDF)
 *
 * 分别对入站/出站方向:
 *   - 全部IP数据报长度的CDF
 *   - TCP载荷的IP数据报长度CDF
 *   - UDP载荷的IP数据报长度CDF
 *   - TCP vs UDP 对比
 */
public class LengthCdfAnalyzer {

    /**
     * 单方向 CDF 数据
     */
    public static class DirectionCdf {
        /** 全部IP分组长度 (已排序) */
        public final int[] allLengths;
        /** TCP载荷IP分组长度 (已排序) */
        public final int[] tcpLengths;
        /** UDP载荷IP分组长度 (已排序) */
        public final int[] udpLengths;

        public DirectionCdf(int[] all, int[] tcp, int[] udp) {
            this.allLengths = all;
            this.tcpLengths = tcp;
            this.udpLengths = udp;
        }
    }

    /**
     * 完整 CDF 分析结果
     */
    public static class Result {
        public final DirectionCdf inbound;
        public final DirectionCdf outbound;

        public Result(DirectionCdf in, DirectionCdf out) {
            this.inbound = in; this.outbound = out;
        }
    }

    /**
     * 执行分析
     */
    public Result analyze(ParseResult parseResult) {
        return new Result(
                buildCdf(parseResult.getInbound()),
                buildCdf(parseResult.getOutbound())
        );
    }

    private DirectionCdf buildCdf(List<IpPacket> packets) {
        List<Integer> all = new ArrayList<>();
        List<Integer> tcp = new ArrayList<>();
        List<Integer> udp = new ArrayList<>();

        for (IpPacket p : packets) {
            int len = p.getTotalLength();
            all.add(len);
            if (p.isTcp()) {
                tcp.add(len);
            } else if (p.isUdp()) {
                udp.add(len);
            }
        }

        Collections.sort(all);
        Collections.sort(tcp);
        Collections.sort(udp);

        return new DirectionCdf(
                toArray(all), toArray(tcp), toArray(udp)
        );
    }

    private int[] toArray(List<Integer> list) {
        return list.stream().mapToInt(Integer::intValue).toArray();
    }
}
