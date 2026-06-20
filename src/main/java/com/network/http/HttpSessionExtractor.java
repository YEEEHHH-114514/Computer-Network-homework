package com.network.http;

/**
 * 第5题: HTTP会话TCP通信拆解
 *
 * 从抓包数据中识别出一次HTTP访问的TCP连接，
 * 按阶段提取:
 *   1. 连接建立 (三次握手)
 *   2. 数据传输 (HTTP请求/响应)
 *   3. 连接释放 (四次挥手)
 *
 * 输出每个分组的: 序号、确认号、窗口值、SYN/ACK/FIN/RST等标志位
 */
public class HttpSessionExtractor {

}
