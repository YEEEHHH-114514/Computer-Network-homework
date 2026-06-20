package com.network.parser;

import com.network.model.IpPacket;
import com.network.model.IpPacket.Direction;
import com.network.model.TcpSegment;
import com.network.model.UdpDatagram;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Packet.IpV4Header;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TcpPacket.TcpHeader;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UdpPacket.UdpHeader;

import java.util.ArrayList;
import java.util.List;

/**
 * PCAP 文件解析器
 *
 * 使用 Pcap4J 读取 Wireshark 抓包文件 (.pcap / .pcapng)，
 * 逐包解析 IPv4/TCP/UDP 各层数据，按本机 IP 判断流量方向，
 * 最终输出 ParseResult 供分析模块使用。
 *
 * 使用方式:
 * <pre>{@code
 *   PcapParser parser = new PcapParser("192.168.1.100");
 *   ParseResult result = parser.parse("captures/capture.pcapng");
 *   System.out.println(result);  // 打印概览
 * }</pre>
 */
public class PcapParser {

    /** 本机 IP 地址，用于判断入站/出站 */
    private final String localIp;

    /**
     * @param localIp 本机 IP 地址 (点分十进制)，用于判定流量方向
     */
    public PcapParser(String localIp) {
        this.localIp = localIp;
    }

    /**
     * 解析 pcap/pcapng 文件，返回按方向分类的 IP 分组列表
     *
     * @param filePath pcap 文件路径
     * @return ParseResult 包含入站/出站 IP 分组列表
     * @throws PcapNativeException 文件打开或读取失败
     * @throws NotOpenException    句柄未打开
     */
    public ParseResult parse(String filePath) throws PcapNativeException, NotOpenException {
        List<IpPacket> inboundPackets = new ArrayList<>();
        List<IpPacket> outboundPackets = new ArrayList<>();

        try (PcapHandle handle = Pcaps.openOffline(filePath)) {
            handle.loop(-1, pcapPacket -> {
                // --- 1. 提取 IPv4 层 ---
                IpV4Packet ipV4 = pcapPacket.get(IpV4Packet.class);
                if (ipV4 == null) return; // 非 IPv4，跳过 (IPv6 / ARP / 其他)

                IpV4Header ipHeader = ipV4.getHeader();
                String srcIp = ipHeader.getSrcAddr().getHostAddress();
                String dstIp = ipHeader.getDstAddr().getHostAddress();

                // --- 2. 判定方向 ---
                Direction direction;
                if (localIp.equals(srcIp)) {
                    direction = Direction.OUTBOUND;
                } else if (localIp.equals(dstIp)) {
                    direction = Direction.INBOUND;
                } else {
                    // 理论上不会发生 (Wireshark 已用 host 过滤)，
                    // 但为健壮性保留此分支
                    return;
                }

                // --- 3. 提取 IP 层字段 ---
                int protocolNumber = ipHeader.getProtocol().value() & 0xFF;
                String protocol = mapProtocol(protocolNumber);
                int totalLength = ipHeader.getTotalLength() & 0xFFFF;
                int headerLength = (ipHeader.getIhl() & 0xFF) * 4;
                int payloadLength = totalLength - headerLength;
                int identification = ipHeader.getIdentification() & 0xFFFF;
                int fragmentOffset = ipHeader.getFragmentOffset() & 0x1FFF;
                boolean moreFragments = ipHeader.getMoreFragmentFlag();
                boolean dontFragment = ipHeader.getDontFragmentFlag();
                int ttl = ipHeader.getTtl() & 0xFF;

                // --- 4. 构建 IP 分组 ---
                IpPacket.Builder ipBuilder = new IpPacket.Builder()
                        .srcIp(srcIp)
                        .dstIp(dstIp)
                        .protocol(protocol)
                        .protocolNumber(protocolNumber)
                        .totalLength(totalLength)
                        .headerLength(headerLength)
                        .payloadLength(payloadLength)
                        .identification(identification)
                        .fragmentOffset(fragmentOffset)
                        .moreFragments(moreFragments)
                        .dontFragment(dontFragment)
                        .ttl(ttl)
                        .direction(direction);

                // --- 5. 提取 TCP / UDP 载荷 ---
                extractTcp(protocolNumber, ipBuilder, pcapPacket, totalLength, headerLength);
                extractUdp(protocolNumber, ipBuilder, pcapPacket);

                IpPacket ipPacket = ipBuilder.build();

                // --- 6. 归类 ---
                if (direction == Direction.INBOUND) {
                    inboundPackets.add(ipPacket);
                } else {
                    outboundPackets.add(ipPacket);
                }
            });
        }

        return new ParseResult(inboundPackets, outboundPackets, filePath, localIp);
    }

    // ======================== 私有方法 ========================

    /**
     * 协议号 → 协议名称映射
     */
    private String mapProtocol(int protocolNumber) {
        switch (protocolNumber) {
            case 6:  return "TCP";
            case 17: return "UDP";
            case 1:  return "ICMP";
            case 2:  return "IGMP";
            default: return "OTHER";
        }
    }

    /**
     * 提取 TCP 层数据并挂载到 IpPacket 上
     */
    private void extractTcp(int protocolNumber, IpPacket.Builder ipBuilder,
                            org.pcap4j.core.PcapPacket pcapPacket,
                            int ipTotalLength, int ipHeaderLength) {
        if (protocolNumber != 6) return; // 非 TCP

        TcpPacket tcpPacket = pcapPacket.get(TcpPacket.class);
        if (tcpPacket == null) return;

        TcpHeader tcpHeader = tcpPacket.getHeader();

        int srcPort = tcpHeader.getSrcPort().valueAsInt();
        int dstPort = tcpHeader.getDstPort().valueAsInt();
        long seqNum  = tcpHeader.getSequenceNumber() & 0xFFFFFFFFL;
        long ackNum  = tcpHeader.getAcknowledgmentNumber() & 0xFFFFFFFFL;
        int tcpHdrLen = (tcpHeader.getDataOffset() & 0xFF) * 4;
        int window   = tcpHeader.getWindow() & 0xFFFF;
        int dataLen  = ipTotalLength - ipHeaderLength - tcpHdrLen;

        TcpSegment segment = new TcpSegment.Builder()
                .srcPort(srcPort)
                .dstPort(dstPort)
                .sequenceNumber(seqNum)
                .ackNumber(ackNum)
                .headerLength(tcpHdrLen)
                .windowSize(window)
                .dataLength(Math.max(dataLen, 0))
                .syn(tcpHeader.getSyn())
                .ack(tcpHeader.getAck())
                .fin(tcpHeader.getFin())
                .rst(tcpHeader.getRst())
                .psh(tcpHeader.getPsh())
                .urg(tcpHeader.getUrg())
                .build();

        ipBuilder.tcpSegment(segment);
    }

    /**
     * 提取 UDP 层数据并挂载到 IpPacket 上
     */
    private void extractUdp(int protocolNumber, IpPacket.Builder ipBuilder,
                            org.pcap4j.core.PcapPacket pcapPacket) {
        if (protocolNumber != 17) return; // 非 UDP

        UdpPacket udpPacket = pcapPacket.get(UdpPacket.class);
        if (udpPacket == null) return;

        UdpHeader udpHeader = udpPacket.getHeader();

        int srcPort  = udpHeader.getSrcPort().valueAsInt();
        int dstPort  = udpHeader.getDstPort().valueAsInt();
        int udpLen   = udpHeader.getLength() & 0xFFFF;
        int dataLen  = udpLen - 8; // UDP 头部固定 8 字节

        UdpDatagram datagram = new UdpDatagram.Builder()
                .srcPort(srcPort)
                .dstPort(dstPort)
                .length(udpLen)
                .dataLength(Math.max(dataLen, 0))
                .build();

        ipBuilder.udpDatagram(datagram);
    }
}
