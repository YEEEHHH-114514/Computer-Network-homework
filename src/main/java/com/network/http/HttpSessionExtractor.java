package com.network.http;

import com.network.model.IpPacket;
import com.network.model.TcpSegment;
import com.network.parser.ParseResult;

import java.util.*;

/**
 * 第5题: HTTP会话TCP通信拆解
 *
 * 从抓包数据中识别出一次 HTTP 访问的 TCP 连接，
 * 按阶段提取分组并生成 HTML 表格:
 *   1. 连接建立 (三次握手)  — SYN → SYN+ACK → ACK
 *   2. 数据传输             — HTTP 请求 / 响应
 *   3. 连接释放 (四次挥手)  — FIN → ACK → FIN → ACK
 *
 * 输出每个分组的: 序号、确认号、窗口值、标志位、数据长度、阶段说明。
 */
public class HttpSessionExtractor {

    /** 单个分组的快照信息 */
    public static class SessionPacket {
        /** 包序号 (连接内) */
        public final int index;
        /** 方向: "发送" 或 "接收" (客户端视角) */
        public final String direction;
        /** 源地址:端口 */
        public final String src;
        /** 目的地址:端口 */
        public final String dst;
        /** TCP 序号 */
        public final long seqNumber;
        /** TCP 确认号 */
        public final long ackNumber;
        /** TCP 窗口大小 */
        public final int windowSize;
        /** 标志位字符串, e.g. "SYN", "SYN+ACK", "PSH+ACK" */
        public final String flags;
        /** TCP 载荷长度 (字节) */
        public final int dataLength;
        /** 阶段说明, e.g. "第一次握手 (SYN)", "HTTP 请求" */
        public final String description;

        SessionPacket(int index, String direction, String src, String dst,
                      long seqNumber, long ackNumber, int windowSize,
                      String flags, int dataLength, String description) {
            this.index = index;
            this.direction = direction;
            this.src = src;
            this.dst = dst;
            this.seqNumber = seqNumber;
            this.ackNumber = ackNumber;
            this.windowSize = windowSize;
            this.flags = flags;
            this.dataLength = dataLength;
            this.description = description;
        }
    }

    /** HTTP 会话完整描述 */
    public static class HttpSession {
        public String clientIp;
        public String serverIp;
        public int clientPort;
        public int serverPort;
        public final List<SessionPacket> handshake = new ArrayList<>();
        public final List<SessionPacket> dataTransfer = new ArrayList<>();
        public final List<SessionPacket> teardown = new ArrayList<>();
        /** 是否包含完整的三阶段 */
        public boolean complete;
        /** 概要文字 */
        public String summary;
    }

    // ==================== 入口 ====================

    /**
     * 从解析结果中提取 HTTP 会话。
     *
     * @param parseResult 已解析的 PCAP 数据
     * @return 最完整的 HTTP 会话; 若未找到 port 80 连接则返回 null
     */
    public HttpSession extract(ParseResult parseResult) {
        // ---- Step 1: 收集所有 port-80 TCP 分组，按连接分组 ----
        Map<String, List<IpPacket>> connections = new LinkedHashMap<>();
        for (IpPacket p : parseResult.getAll()) {
            if (!p.isTcp() || p.getTcpSegment() == null) continue;
            TcpSegment tcp = p.getTcpSegment();
            if (tcp.getSrcPort() != 80 && tcp.getDstPort() != 80) continue;

            String key = connectionKey(p, tcp);
            connections.computeIfAbsent(key, k -> new ArrayList<>()).add(p);
        }

        if (connections.isEmpty()) return null;

        // ---- Step 2: 对每个候选连接提取会话，按完整度选择最佳 ----
        HttpSession best = null;
        int bestScore = -1;

        for (List<IpPacket> connPackets : connections.values()) {
            HttpSession session = extractSession(connPackets);
            if (session == null) continue;
            int score = score(session);
            if (score > bestScore) {
                bestScore = score;
                best = session;
            }
        }

        return best;
    }

    // ==================== 连接识别 ====================

    /**
     * 生成连接标识键: "clientIp|serverIp|clientPort|80"
     * dstPort == 80 的一端是服务器。
     */
    private String connectionKey(IpPacket p, TcpSegment tcp) {
        if (tcp.getDstPort() == 80) {
            return p.getSrcIp() + "|" + p.getDstIp() + "|" + tcp.getSrcPort() + "|80";
        } else {
            return p.getDstIp() + "|" + p.getSrcIp() + "|" + tcp.getDstPort() + "|80";
        }
    }

    // ==================== 阶段提取 ====================

    /**
     * 对一个连接的所有分组按标志位识别三阶段。
     *
     * 状态机:
     *   握手: SYN(!ACK) → SYN+ACK → ACK(!SYN, dataLen=0)
     *   传输: 所有非 FIN 分组
     *   挥手: FIN → ACK(!FIN) → FIN → ACK(!FIN)
     */
    private HttpSession extractSession(List<IpPacket> packets) {
        HttpSession session = new HttpSession();

        // 确定客户端/服务器角色
        IpPacket first = packets.get(0);
        TcpSegment firstTcp = first.getTcpSegment();
        if (firstTcp.getDstPort() == 80) {
            session.clientIp = first.getSrcIp();
            session.serverIp = first.getDstIp();
            session.clientPort = firstTcp.getSrcPort();
            session.serverPort = 80;
        } else {
            session.clientIp = first.getDstIp();
            session.serverIp = first.getSrcIp();
            session.clientPort = firstTcp.getDstPort();
            session.serverPort = 80;
        }

        int handshakeStep = 0;   // 0→1→2→3(done)
        int teardownStep = 0;    // 0→1→2→3→4(done)
        boolean handshakeDone = false;
        boolean inTeardown = false;
        int pktIdx = 0;

        for (IpPacket p : packets) {
            TcpSegment tcp = p.getTcpSegment();
            boolean toServer = p.getSrcIp().equals(session.clientIp);
            String dir = toServer ? "发送" : "接收";
            String src = p.getSrcIp() + ":" + tcp.getSrcPort();
            String dst = p.getDstIp() + ":" + tcp.getDstPort();
            String flags = tcp.getFlagsString();
            String desc;
            pktIdx++;

            if (!handshakeDone) {
                // ===== 握手阶段 =====
                if (handshakeStep == 0 && tcp.isSyn() && !tcp.isAck()) {
                    desc = "第一次握手 (SYN)";
                    handshakeStep = 1;
                } else if (handshakeStep == 1 && tcp.isSyn() && tcp.isAck()) {
                    desc = "第二次握手 (SYN+ACK)";
                    handshakeStep = 2;
                } else if (handshakeStep == 2 && tcp.isAck() && !tcp.isSyn()
                        && tcp.getDataLength() == 0) {
                    desc = "第三次握手 (ACK)";
                    handshakeStep = 3;
                    handshakeDone = true;
                } else {
                    desc = "握手阶段";
                }
                session.handshake.add(buildPacket(pktIdx, dir, src, dst, tcp, flags, desc));

            } else if (!inTeardown) {
                // ===== 数据传输阶段 =====
                if (tcp.isFin()) {
                    inTeardown = true;
                    desc = tcp.isAck() ? "第一次挥手 (FIN+ACK)" : "第一次挥手 (FIN)";
                    teardownStep = 1;
                    session.teardown.add(buildPacket(pktIdx, dir, src, dst, tcp, flags, desc));
                } else {
                    if (tcp.getDataLength() > 0 && toServer) {
                        desc = "HTTP 请求";
                    } else if (tcp.getDataLength() > 0 && !toServer) {
                        desc = "HTTP 响应数据";
                    } else {
                        desc = "确认 (ACK)";
                    }
                    session.dataTransfer.add(buildPacket(pktIdx, dir, src, dst, tcp, flags, desc));
                }

            } else {
                // ===== 挥手阶段 =====
                if (teardownStep == 1 && tcp.isAck() && !tcp.isFin()) {
                    desc = "第二次挥手 (ACK)";
                    teardownStep = 2;
                } else if (teardownStep == 2 && tcp.isFin()) {
                    desc = tcp.isAck() ? "第三次挥手 (FIN+ACK)" : "第三次挥手 (FIN)";
                    teardownStep = 3;
                } else if (teardownStep == 3 && tcp.isAck() && !tcp.isFin()) {
                    desc = "第四次挥手 (ACK)";
                    teardownStep = 4;
                } else {
                    desc = "挥手阶段";
                }
                session.teardown.add(buildPacket(pktIdx, dir, src, dst, tcp, flags, desc));
            }
        }

        session.complete = (handshakeStep == 3) && !session.dataTransfer.isEmpty();
        session.summary = String.format(
                "客户端 %s:%d → 服务器 %s:%d | 握手: %d 包 | 数据: %d 包 | 挥手: %d 包",
                session.clientIp, session.clientPort,
                session.serverIp, session.serverPort,
                session.handshake.size(), session.dataTransfer.size(),
                session.teardown.size());
        return session;
    }

    private SessionPacket buildPacket(int index, String dir, String src, String dst,
                                      TcpSegment tcp, String flags, String desc) {
        return new SessionPacket(index, dir, src, dst,
                tcp.getSequenceNumber(), tcp.getAckNumber(),
                tcp.getWindowSize(), flags, tcp.getDataLength(), desc);
    }

    /** 评分会话完整度 (选择最佳连接用) */
    private int score(HttpSession session) {
        int s = 0;
        if (session.handshake.size() >= 3) s += 30;
        else if (!session.handshake.isEmpty()) s += 10;
        if (!session.dataTransfer.isEmpty()) s += 20 + Math.min(session.dataTransfer.size(), 50);
        if (session.teardown.size() >= 3) s += 15;
        else if (!session.teardown.isEmpty()) s += 5;
        return s;
    }

    // ==================== HTML 生成 ====================

    /**
     * 将会话转换为 HTML 表格片段，直接嵌入 report.html。
     *
     * @param session 已提取的 HTTP 会话 (可为 null)
     * @return HTML 字符串
     */
    public String toHtmlTable(HttpSession session) {
        if (session == null) {
            return "<p class=\"note\">未找到 HTTP 会话 (无 port 80 TCP 连接)</p>";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("<p><strong>HTTP 会话: </strong>").append(session.summary).append("</p>\n");

        // 阶段一: 握手
        if (!session.handshake.isEmpty()) {
            sb.append("<h4>阶段一: 连接建立 (三次握手)</h4>\n");
            appendTable(sb, session.handshake);
        }

        // 阶段二: 数据传输
        if (!session.dataTransfer.isEmpty()) {
            sb.append("<h4>阶段二: 数据传输</h4>\n");
            appendTable(sb, session.dataTransfer);
        }

        // 阶段三: 挥手
        if (!session.teardown.isEmpty()) {
            sb.append("<h4>阶段三: 连接释放 (四次挥手)</h4>\n");
            appendTable(sb, session.teardown);
        }

        return sb.toString();
    }

    private void appendTable(StringBuilder sb, List<SessionPacket> packets) {
        sb.append("<table><tr>")
          .append("<th>序号</th><th>方向</th>")
          .append("<th>源地址:端口</th><th>目的地址:端口</th>")
          .append("<th>Seq (序号)</th><th>Ack (确认号)</th>")
          .append("<th>Window (窗口)</th><th>Flags (标志位)</th>")
          .append("<th>数据长度</th><th>说明</th></tr>\n");

        for (SessionPacket p : packets) {
            sb.append("<tr>");
            sb.append("<td>").append(p.index).append("</td>");
            sb.append("<td>").append(p.direction).append("</td>");
            sb.append("<td>").append(p.src).append("</td>");
            sb.append("<td>").append(p.dst).append("</td>");
            sb.append("<td class=\"value\">").append(p.seqNumber).append("</td>");
            sb.append("<td class=\"value\">").append(p.ackNumber).append("</td>");
            sb.append("<td class=\"value\">").append(p.windowSize).append("</td>");
            sb.append("<td>").append(p.flags).append("</td>");
            sb.append("<td>").append(p.dataLength).append("</td>");
            sb.append("<td>").append(p.description).append("</td>");
            sb.append("</tr>\n");
        }
        sb.append("</table>\n");
    }
}
