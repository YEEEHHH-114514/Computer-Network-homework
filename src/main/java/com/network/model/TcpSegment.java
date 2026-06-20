package com.network.model;

/**
 * TCP 段数据模型
 *
 * 保存 TCP 头部全部关键字段及载荷长度，
 * 用于分析模块和 HTTP 会话提取。
 */
public class TcpSegment {

    // ======================== TCP 头部字段 ========================

    /** 源端口号 */
    private final int srcPort;
    /** 目的端口号 */
    private final int dstPort;
    /** 序号 (Sequence Number) */
    private final long sequenceNumber;
    /** 确认号 (Acknowledgment Number) */
    private final long ackNumber;
    /** TCP 头部长度 (单位: 字节) */
    private final int headerLength;
    /** 窗口大小 */
    private final int windowSize;
    /** TCP 载荷长度 (单位: 字节) */
    private final int dataLength;

    // ======================== 控制位 ========================

    private final boolean syn;
    private final boolean ack;
    private final boolean fin;
    private final boolean rst;
    private final boolean psh;
    private final boolean urg;

    // ======================== 构造函数 ========================

    private TcpSegment(Builder builder) {
        this.srcPort = builder.srcPort;
        this.dstPort = builder.dstPort;
        this.sequenceNumber = builder.sequenceNumber;
        this.ackNumber = builder.ackNumber;
        this.headerLength = builder.headerLength;
        this.windowSize = builder.windowSize;
        this.dataLength = builder.dataLength;
        this.syn = builder.syn;
        this.ack = builder.ack;
        this.fin = builder.fin;
        this.rst = builder.rst;
        this.psh = builder.psh;
        this.urg = builder.urg;
    }

    // ======================== Getters ========================

    public int getSrcPort() { return srcPort; }
    public int getDstPort() { return dstPort; }
    public long getSequenceNumber() { return sequenceNumber; }
    public long getAckNumber() { return ackNumber; }
    public int getHeaderLength() { return headerLength; }
    public int getWindowSize() { return windowSize; }
    public int getDataLength() { return dataLength; }
    public boolean isSyn() { return syn; }
    public boolean isAck() { return ack; }
    public boolean isFin() { return fin; }
    public boolean isRst() { return rst; }
    public boolean isPsh() { return psh; }
    public boolean isUrg() { return urg; }

    /** 标志位组合字符串，如 "SYN", "SYN+ACK", "PSH+ACK" */
    public String getFlagsString() {
        StringBuilder sb = new StringBuilder();
        if (syn) sb.append("SYN+");
        if (ack) sb.append("ACK+");
        if (fin) sb.append("FIN+");
        if (rst) sb.append("RST+");
        if (psh) sb.append("PSH+");
        if (urg) sb.append("URG+");
        if (sb.length() == 0) return "NONE";
        return sb.substring(0, sb.length() - 1);
    }

    @Override
    public String toString() {
        return String.format("TCP[%d→%d, Seq=%d, Ack=%d, Win=%d, %s, dataLen=%d]",
                srcPort, dstPort, sequenceNumber, ackNumber, windowSize,
                getFlagsString(), dataLength);
    }

    // ======================== Builder ========================

    public static class Builder {
        private int srcPort;
        private int dstPort;
        private long sequenceNumber;
        private long ackNumber;
        private int headerLength;
        private int windowSize;
        private int dataLength;
        private boolean syn, ack, fin, rst, psh, urg;

        public Builder srcPort(int val)         { this.srcPort = val; return this; }
        public Builder dstPort(int val)         { this.dstPort = val; return this; }
        public Builder sequenceNumber(long val) { this.sequenceNumber = val; return this; }
        public Builder ackNumber(long val)      { this.ackNumber = val; return this; }
        public Builder headerLength(int val)    { this.headerLength = val; return this; }
        public Builder windowSize(int val)      { this.windowSize = val; return this; }
        public Builder dataLength(int val)      { this.dataLength = val; return this; }
        public Builder syn(boolean val)         { this.syn = val; return this; }
        public Builder ack(boolean val)         { this.ack = val; return this; }
        public Builder fin(boolean val)         { this.fin = val; return this; }
        public Builder rst(boolean val)         { this.rst = val; return this; }
        public Builder psh(boolean val)         { this.psh = val; return this; }
        public Builder urg(boolean val)         { this.urg = val; return this; }

        public TcpSegment build() { return new TcpSegment(this); }
    }
}
