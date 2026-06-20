package com.network.model;

/**
 * IP 分组数据模型
 *
 * 保存 IPv4 分组的完整头部信息及载荷(TCP/UDP)引用，
 * 同时标记流量方向(入站/出站)。
 */
public class IpPacket {

    /** 流量方向 */
    public enum Direction {
        INBOUND,   // dstIp == 本机IP
        OUTBOUND   // srcIp == 本机IP
    }

    // ======================== IP 头部字段 ========================

    /** 源 IP 地址 (点分十进制) */
    private final String srcIp;
    /** 目的 IP 地址 (点分十进制) */
    private final String dstIp;
    /** 传输层协议名称: "TCP", "UDP", "ICMP", "OTHER" */
    private final String protocol;
    /** IP 协议号 (6=TCP, 17=UDP, 1=ICMP, ...) */
    private final int protocolNumber;
    /** IP 总长度 (头部+载荷, 单位: 字节) */
    private final int totalLength;
    /** IP 头部长度 (单位: 字节) */
    private final int headerLength;
    /** 载荷长度 = totalLength - headerLength (单位: 字节) */
    private final int payloadLength;
    /** 标识字段 (Identification), 用于分片重组 */
    private final int identification;
    /** 片偏移 (单位: 8字节) */
    private final int fragmentOffset;
    /** MF 标志 (More Fragments) */
    private final boolean moreFragments;
    /** DF 标志 (Don't Fragment) */
    private final boolean dontFragment;
    /** 是否为分片 (MF=1 或 片偏移>0) */
    private final boolean fragment;
    /** 存活时间 */
    private final int ttl;
    /** 流量方向 */
    private final Direction direction;

    // ======================== 载荷引用 ========================

    /** TCP 段 (仅当 protocol=="TCP" 时非 null) */
    private final TcpSegment tcpSegment;
    /** UDP 数据报 (仅当 protocol=="UDP" 时非 null) */
    private final UdpDatagram udpDatagram;

    // ======================== 构造函数 ========================

    private IpPacket(Builder builder) {
        this.srcIp = builder.srcIp;
        this.dstIp = builder.dstIp;
        this.protocol = builder.protocol;
        this.protocolNumber = builder.protocolNumber;
        this.totalLength = builder.totalLength;
        this.headerLength = builder.headerLength;
        this.payloadLength = builder.payloadLength;
        this.identification = builder.identification;
        this.fragmentOffset = builder.fragmentOffset;
        this.moreFragments = builder.moreFragments;
        this.dontFragment = builder.dontFragment;
        this.fragment = (builder.fragmentOffset > 0) || builder.moreFragments;
        this.ttl = builder.ttl;
        this.direction = builder.direction;
        this.tcpSegment = builder.tcpSegment;
        this.udpDatagram = builder.udpDatagram;
    }

    // ======================== Getters ========================

    public String getSrcIp() { return srcIp; }
    public String getDstIp() { return dstIp; }
    public String getProtocol() { return protocol; }
    public int getProtocolNumber() { return protocolNumber; }
    public int getTotalLength() { return totalLength; }
    public int getHeaderLength() { return headerLength; }
    public int getPayloadLength() { return payloadLength; }
    public int getIdentification() { return identification; }
    public int getFragmentOffset() { return fragmentOffset; }
    public boolean isMoreFragments() { return moreFragments; }
    public boolean isDontFragment() { return dontFragment; }
    public boolean isFragment() { return fragment; }
    public int getTtl() { return ttl; }
    public Direction getDirection() { return direction; }
    public TcpSegment getTcpSegment() { return tcpSegment; }
    public UdpDatagram getUdpDatagram() { return udpDatagram; }

    /** 载荷为 TCP 的分组 */
    public boolean isTcp() { return "TCP".equals(protocol); }
    /** 载荷为 UDP 的分组 */
    public boolean isUdp() { return "UDP".equals(protocol); }
    /** 入站流量 */
    public boolean isInbound() { return direction == Direction.INBOUND; }
    /** 出站流量 */
    public boolean isOutbound() { return direction == Direction.OUTBOUND; }

    @Override
    public String toString() {
        return String.format("IP[%s → %s, %s, len=%d, %s]",
                srcIp, dstIp, protocol, totalLength, direction);
    }

    // ======================== Builder ========================

    public static class Builder {
        private String srcIp;
        private String dstIp;
        private String protocol = "OTHER";
        private int protocolNumber;
        private int totalLength;
        private int headerLength;
        private int payloadLength;
        private int identification;
        private int fragmentOffset;
        private boolean moreFragments;
        private boolean dontFragment;
        private int ttl;
        private Direction direction;
        private TcpSegment tcpSegment;
        private UdpDatagram udpDatagram;

        public Builder srcIp(String val)         { this.srcIp = val; return this; }
        public Builder dstIp(String val)         { this.dstIp = val; return this; }
        public Builder protocol(String val)      { this.protocol = val; return this; }
        public Builder protocolNumber(int val)   { this.protocolNumber = val; return this; }
        public Builder totalLength(int val)      { this.totalLength = val; return this; }
        public Builder headerLength(int val)     { this.headerLength = val; return this; }
        public Builder payloadLength(int val)    { this.payloadLength = val; return this; }
        public Builder identification(int val)   { this.identification = val; return this; }
        public Builder fragmentOffset(int val)   { this.fragmentOffset = val; return this; }
        public Builder moreFragments(boolean val){ this.moreFragments = val; return this; }
        public Builder dontFragment(boolean val) { this.dontFragment = val; return this; }
        public Builder ttl(int val)              { this.ttl = val; return this; }
        public Builder direction(Direction val)  { this.direction = val; return this; }
        public Builder tcpSegment(TcpSegment val){ this.tcpSegment = val; return this; }
        public Builder udpDatagram(UdpDatagram val) { this.udpDatagram = val; return this; }

        public IpPacket build() { return new IpPacket(this); }
    }
}
