package com.network.parser;

import com.network.model.IpPacket;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 解析结果容器
 *
 * 将 PcapParser 解析后的 IP 分组按入站/出站分开存放，
 * 供后续分析模块使用。
 */
public class ParseResult {

    /** 入站分组列表 (dstIp == 本机IP) */
    private final List<IpPacket> inbound;

    /** 出站分组列表 (srcIp == 本机IP) */
    private final List<IpPacket> outbound;

    /** 全部 IP 分组 */
    private final List<IpPacket> all;

    /** 原始 pcap 文件路径 */
    private final String sourceFile;

    /** 本机 IP 地址 */
    private final String localIp;

    /** 解析到的 IP 分组总数 */
    private final int totalIpPackets;

    public ParseResult(List<IpPacket> inbound, List<IpPacket> outbound,
                       List<IpPacket> all, String sourceFile, String localIp) {
        this.inbound = Collections.unmodifiableList(new ArrayList<>(inbound));
        this.outbound = Collections.unmodifiableList(new ArrayList<>(outbound));
        this.all = Collections.unmodifiableList(new ArrayList<>(all));
        this.sourceFile = sourceFile;
        this.localIp = localIp;
        this.totalIpPackets = inbound.size() + outbound.size();
    }

    // ======================== Getters ========================

    /** 入站分组 (只读) */
    public List<IpPacket> getInbound() { return inbound; }
    /** 出站分组 (只读) */
    public List<IpPacket> getOutbound() { return outbound; }
    /** 全部分组 (只读) */
    public List<IpPacket> getAll() { return all; }
    /** 源 pcap 文件路径 */
    public String getSourceFile() { return sourceFile; }
    /** 本机 IP */
    public String getLocalIp() { return localIp; }
    /** IP 分组总数 */
    public int getTotalIpPackets() { return totalIpPackets; }

    /** 获取所有 TCP 分组 */
    public List<IpPacket> getTcpPackets() {
        return all.stream().filter(IpPacket::isTcp).toList();
    }

    /** 获取所有 UDP 分组 */
    public List<IpPacket> getUdpPackets() {
        return all.stream().filter(IpPacket::isUdp).toList();
    }

    @Override
    public String toString() {
        return String.format("ParseResult[file=%s, local=%s, inbound=%d, outbound=%d, total=%d]",
                sourceFile, localIp, inbound.size(), outbound.size(), totalIpPackets);
    }
}
