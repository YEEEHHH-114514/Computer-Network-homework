package com.network.model;

/**
 * UDP 数据报数据模型
 *
 * 保存 UDP 头部字段及载荷长度。
 */
public class UdpDatagram {

    // ======================== UDP 头部字段 ========================

    /** 源端口号 */
    private final int srcPort;
    /** 目的端口号 */
    private final int dstPort;
    /** UDP 总长度 (头部+载荷, 单位: 字节) */
    private final int length;
    /** UDP 载荷长度 = length - 8 (头部固定8字节) */
    private final int dataLength;

    // ======================== 构造函数 ========================

    private UdpDatagram(Builder builder) {
        this.srcPort = builder.srcPort;
        this.dstPort = builder.dstPort;
        this.length = builder.length;
        this.dataLength = builder.dataLength;
    }

    // ======================== Getters ========================

    public int getSrcPort() { return srcPort; }
    public int getDstPort() { return dstPort; }
    public int getLength() { return length; }
    public int getDataLength() { return dataLength; }

    @Override
    public String toString() {
        return String.format("UDP[%d→%d, len=%d, dataLen=%d]",
                srcPort, dstPort, length, dataLength);
    }

    // ======================== Builder ========================

    public static class Builder {
        private int srcPort;
        private int dstPort;
        private int length;
        private int dataLength;

        public Builder srcPort(int val)      { this.srcPort = val; return this; }
        public Builder dstPort(int val)      { this.dstPort = val; return this; }
        public Builder length(int val)       { this.length = val; return this; }
        public Builder dataLength(int val)   { this.dataLength = val; return this; }

        public UdpDatagram build() { return new UdpDatagram(this); }
    }
}
