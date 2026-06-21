package com.network.report;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;

import com.network.analysis.FragmentAnalyzer;
import com.network.analysis.PortHistogramAnalyzer;

/**
 * HTML 报告生成器
 *
 * 将全部分析数据和图表组装为单页 HTML，输出到 output/report.html。
 * 浏览器打开即可查看，图表和数据表格方便直接复制到 Word 实验报告。
 */
public class HtmlGenerator {

    private final String outputPath;

    public HtmlGenerator(String outputPath) {
        this.outputPath = outputPath;
    }

    // ==================== 报告入口 ====================

    /**
     * 生成完整报告
     *
     * @param ctx 报告上下文 (包含所有分析结果和图表路径)
     */
    public void generate(ReportContext ctx) throws IOException {
        try (PrintWriter w = new PrintWriter(new FileWriter(outputPath))) {
            htmlStart(w);
            writeHeader(w, ctx);
            writeSection1_ProtocolPie(w, ctx);
            writeSection2_Fragment(w, ctx);
            writeSection3_LengthCdf(w, ctx);
            writeSection4_PortHistogram(w, ctx);
            writeSection5_TcpFlags(w, ctx);
            writeSection6_HttpSession(w, ctx);
            htmlEnd(w);
        }
    }

    // ==================== HTML 框架 ====================

    private void htmlStart(PrintWriter w) {
        w.println("<!DOCTYPE html><html lang=\"zh-CN\"><head>");
        w.println("<meta charset=\"UTF-8\">");
        w.println("<title>计算机网络课程大作业 - 流量分析报告</title>");
        w.println("<style>");
        w.println("body{font-family:'Microsoft YaHei',sans-serif;max-width:1100px;margin:0 auto;padding:20px;background:#f5f5f5;color:#333}");
        w.println("h1{text-align:center;color:#1a5276;border-bottom:3px solid #2980b9;padding-bottom:10px}");
        w.println("h2{color:#2471a3;border-left:4px solid #2980b9;padding-left:10px;margin-top:40px}");
        w.println(".meta{text-align:center;color:#666;font-size:14px;margin-bottom:30px}");
        w.println(".charts{display:flex;flex-wrap:wrap;gap:20px;justify-content:center;margin:15px 0}");
        w.println(".charts img{max-width:600px;border:1px solid #ddd;box-shadow:2px 2px 6px rgba(0,0,0,0.1);background:#fff}");
        w.println("table{border-collapse:collapse;width:100%;margin:10px 0;background:#fff;box-shadow:1px 1px 4px rgba(0,0,0,0.08)}");
        w.println("th,td{border:1px solid #ccc;padding:8px 12px;text-align:center}");
        w.println("th{background:#2980b9;color:#fff;font-weight:bold}");
        w.println("tr:nth-child(even){background:#f0f5fa}");
        w.println(".value{font-weight:bold;color:#1a5276}");
        w.println(".note{color:#999;font-size:13px;margin:5px 0 20px 0}");
        w.println(".footer{text-align:center;color:#999;margin-top:50px;padding-top:20px;border-top:1px solid #ddd}");
        w.println("</style></head><body>");
    }

    private void htmlEnd(PrintWriter w) {
        w.println("<div class=\"footer\">计算机网络课程大作业 &copy; 2026</div>");
        w.println("</body></html>");
    }

    // ==================== 报告头部 ====================

    private void writeHeader(PrintWriter w, ReportContext ctx) {
        w.println("<h1>计算机网络课程大作业</h1>");
        w.println("<h1 style=\"font-size:20px;border:none;color:#555\">流量采集、分析与可视化</h1>");
        w.println("<div class=\"meta\">");
        w.println("<p>本机IP: <strong>" + ctx.localIp + "</strong> &nbsp;|&nbsp; "
                + "数据文件: <strong>" + ctx.sourceFile + "</strong> &nbsp;|&nbsp; "
                + "IP分组总数: <strong>" + ctx.totalPackets + "</strong></p>");
        w.println("</div>");
    }

    // ==================== 分析1: 协议分布 ====================

    private void writeSection1_ProtocolPie(PrintWriter w, ReportContext ctx) {
        w.println("<h2>一、IP分组协议载荷分布</h2>");

        // 入站
        w.println("<h3>入站方向</h3>");
        w.println("<div class=\"charts\">");
        w.println("<img src=\"charts/" + ctx.chartProtoInCount + "\" alt=\"入站-分组数\">");
        w.println("<img src=\"charts/" + ctx.chartProtoInVolume + "\" alt=\"入站-数据量\">");
        w.println("</div>");
        writeProtocolTable(w, ctx.protoInCounts, ctx.protoInVolumes);

        // 出站
        w.println("<h3>出站方向</h3>");
        w.println("<div class=\"charts\">");
        w.println("<img src=\"charts/" + ctx.chartProtoOutCount + "\" alt=\"出站-分组数\">");
        w.println("<img src=\"charts/" + ctx.chartProtoOutVolume + "\" alt=\"出站-数据量\">");
        w.println("</div>");
        writeProtocolTable(w, ctx.protoOutCounts, ctx.protoOutVolumes);
    }

    private void writeProtocolTable(PrintWriter w, Map<String, Integer> counts, Map<String, Long> volumes) {
        w.println("<table><tr><th>协议</th><th>分组数</th><th>占比</th><th>总数据量(字节)</th><th>占比</th></tr>");
        int totalCount = counts.values().stream().mapToInt(Integer::intValue).sum();
        long totalVolume = volumes.values().stream().mapToLong(Long::longValue).sum();
        for (String proto : new String[]{"TCP", "UDP", "ICMP", "OTHER"}) {
            int c = counts.getOrDefault(proto, 0);
            long v = volumes.getOrDefault(proto, 0L);
            double pctC = totalCount > 0 ? 100.0 * c / totalCount : 0;
            double pctV = totalVolume > 0 ? 100.0 * v / totalVolume : 0;
            w.printf("<tr><td>%s</td><td class=\"value\">%d</td><td>%.1f%%</td>"
                            + "<td class=\"value\">%,d</td><td>%.1f%%</td></tr>%n",
                    proto, c, pctC, v, pctV);
        }
        w.println("</table>");
    }

    // ==================== 分析2: 分片统计 ====================

    private void writeSection2_Fragment(PrintWriter w, ReportContext ctx) {
        w.println("<h2>二、IP分片分析</h2>");
        w.println("<table><tr>"
                + "<th>方向</th><th>IP分组总数</th><th>片段(fragment)数</th>"
                + "<th>被分片的数据报数</th><th>TCP被分片比例</th><th>UDP被分片比例</th></tr>");

        writeFragRow(w, "入站", ctx.fragIn);
        writeFragRow(w, "出站", ctx.fragOut);
        w.println("</table>");
        w.println("<p class=\"note\">* 被分片的数据报数按 (源IP, 目的IP, 协议, 标识) 归组统计</p>");
    }

    private void writeFragRow(PrintWriter w, String label, FragmentAnalyzer.DirectionResult r) {
        w.printf("<tr><td>%s</td><td class=\"value\">%d</td><td class=\"value\">%d</td>"
                        + "<td class=\"value\">%d</td><td class=\"value\">%.2f%%</td>"
                        + "<td class=\"value\">%.2f%%</td></tr>%n",
                label, r.totalPacketCount, r.fragmentPacketCount,
                r.fragmentedDatagramCount,
                r.tcpFragmentedRatio * 100, r.udpFragmentedRatio * 100);
    }

    // ==================== 分析3: 长度 CDF ====================

    private void writeSection3_LengthCdf(PrintWriter w, ReportContext ctx) {
        w.println("<h2>三、IP数据报长度累积分布 (CDF)</h2>");

        w.println("<h3>入站方向</h3>");
        w.println("<div class=\"charts\">");
        w.println("<img src=\"charts/" + ctx.chartCdfIn + "\" alt=\"入站CDF\">");
        w.println("</div>");

        w.println("<h3>出站方向</h3>");
        w.println("<div class=\"charts\">");
        w.println("<img src=\"charts/" + ctx.chartCdfOut + "\" alt=\"出站CDF\">");
        w.println("</div>");
    }

    // ==================== 分析4: 端口分布 ====================

    private void writeSection4_PortHistogram(PrintWriter w, ReportContext ctx) {
        w.println("<h2>四、TCP/UDP 端口分布</h2>");

        writePortSection(w, "TCP 入站", ctx.chartTcpInHist, ctx.chartTcpInCdf, ctx.portTcpIn);
        writePortSection(w, "TCP 出站", ctx.chartTcpOutHist, ctx.chartTcpOutCdf, ctx.portTcpOut);
        writePortSection(w, "UDP 入站", ctx.chartUdpInHist, ctx.chartUdpInCdf, ctx.portUdpIn);
        writePortSection(w, "UDP 出站", ctx.chartUdpOutHist, ctx.chartUdpOutCdf, ctx.portUdpOut);
    }

    private void writePortSection(PrintWriter w, String title,
                                  String histChart, String cdfChart,
                                  PortHistogramAnalyzer.ProtocolPortResult result) {
        w.println("<h3>" + title + "</h3>");
        w.println("<div class=\"charts\">");
        w.println("<img src=\"charts/" + histChart + "\" alt=\"" + title + "直方图\">");
        if (cdfChart != null) {
            w.println("<img src=\"charts/" + cdfChart + "\" alt=\"" + title + " Top10 CDF\">");
        }
        w.println("</div>");

        // Top 10 端口表格
        w.println("<table><tr><th>排名</th><th>端口号</th><th>出现次数</th></tr>");
        int rank = 1;
        for (Map.Entry<Integer, Integer> e : result.topPorts) {
            w.printf("<tr><td>%d</td><td class=\"value\">%d</td><td class=\"value\">%d</td></tr>%n",
                    rank++, e.getKey(), e.getValue());
        }
        w.println("</table>");
    }

    // ==================== 分析5: TCP 控制位 ====================

    private void writeSection5_TcpFlags(PrintWriter w, ReportContext ctx) {
        w.println("<h2>五、TCP 控制位出现百分比</h2>");
        w.println("<div class=\"charts\">");
        w.println("<img src=\"charts/" + ctx.chartTcpFlags + "\" alt=\"TCP控制位\">");
        w.println("</div>");

        w.println("<table><tr><th>控制位</th><th>入站 (%)</th><th>出站 (%)</th></tr>");
        for (String flag : new String[]{"SYN", "ACK", "FIN", "RST", "PSH", "URG"}) {
            double inPct = ctx.tcpFlagsIn.getOrDefault(flag, 0.0);
            double outPct = ctx.tcpFlagsOut.getOrDefault(flag, 0.0);
            w.printf("<tr><td>%s</td><td class=\"value\">%.1f%%</td><td class=\"value\">%.1f%%</td></tr>%n",
                    flag, inPct, outPct);
        }
        w.println("</table>");
        w.printf("<p class=\"note\">入站TCP分组: %d &nbsp;|&nbsp; 出站TCP分组: %d</p>%n",
                ctx.tcpInCount, ctx.tcpOutCount);
    }

    // ==================== 分析6: HTTP 会话 (占位) ====================

    private void writeSection6_HttpSession(PrintWriter w, ReportContext ctx) {
        w.println("<h2>六、HTTP 访问 TCP 通信拆解</h2>");
        if (ctx.httpSessionTable == null) {
            w.println("<p class=\"note\">(待实现: HttpSessionExtractor 解析 HTTP 会话后填入)</p>");
        } else {
            w.println(ctx.httpSessionTable);
        }
    }
}
