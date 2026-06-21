package com.network.report;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartUtils;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.general.DefaultPieDataset;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;

import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * 图表生成器 — 使用 JFreeChart 将分析数据渲染为 PNG
 *
 * 输出目录: output/charts/
 */
public class ChartGenerator {

    private final String outputDir;

    public ChartGenerator(String outputDir) {
        this.outputDir = outputDir;
        new File(outputDir).mkdirs();
    }

    // ==================== 1. 协议分布饼图 ====================

    /**
     * 生成协议分布饼图 (按分组数或数据量)
     * @return 生成的 PNG 文件路径
     */
    public String generateProtocolPie(Map<String, ? extends Number> data,
                                      String title, String filename) throws IOException {
        DefaultPieDataset<String> dataset = new DefaultPieDataset<>();
        for (Map.Entry<String, ? extends Number> e : data.entrySet()) {
            double val = e.getValue().doubleValue();
            if (val > 0) {
                dataset.setValue(e.getKey(), val);
            }
        }

        JFreeChart chart = ChartFactory.createPieChart(
                title, dataset, true, true, false);

        return saveChart(chart, filename, 600, 450);
    }

    // ==================== 2. CDF 曲线图 ====================

    /**
     * 生成 CDF (累积分布) 曲线图
     *
     * @param seriesMap 系列名 → 排序后的数据数组
     */
    public String generateCdfChart(Map<String, int[]> seriesMap,
                                   String title, String xLabel, String filename) throws IOException {
        XYSeriesCollection dataset = new XYSeriesCollection();

        for (Map.Entry<String, int[]> entry : seriesMap.entrySet()) {
            int[] sorted = entry.getValue();
            XYSeries series = new XYSeries(entry.getKey());
            int n = sorted.length;
            for (int i = 0; i < n; i++) {
                double cdf = (i + 1.0) / n;  // 累积概率
                series.add(sorted[i], cdf);
            }
            dataset.addSeries(series);
        }

        JFreeChart chart = ChartFactory.createXYLineChart(
                title, xLabel, "CDF (累积概率)", dataset,
                PlotOrientation.VERTICAL, true, true, false);

        return saveChart(chart, filename, 700, 500);
    }

    // ==================== 3. 端口分布直方图 ====================

    /**
     * 生成端口频率直方图 (Top N 端口)
     */
    public String generatePortHistogram(List<Map.Entry<Integer, Integer>> topPorts,
                                        String title, String filename) throws IOException {
        DefaultCategoryDataset dataset = new DefaultCategoryDataset();
        for (Map.Entry<Integer, Integer> e : topPorts) {
            dataset.addValue(e.getValue(), "频次", String.valueOf(e.getKey()));
        }

        JFreeChart chart = ChartFactory.createBarChart(
                title, "端口号", "出现次数", dataset,
                PlotOrientation.VERTICAL, false, true, false);

        return saveChart(chart, filename, 700, 450);
    }

    // ==================== 4. TCP 控制位柱状图 ====================

    /**
     * 生成 TCP 控制位百分比柱状图
     */
    public String generateTcpFlagsChart(Map<String, Double> inboundPct,
                                        Map<String, Double> outboundPct,
                                        String filename) throws IOException {
        DefaultCategoryDataset dataset = new DefaultCategoryDataset();
        for (Map.Entry<String, Double> e : inboundPct.entrySet()) {
            dataset.addValue(e.getValue(), "入站", e.getKey());
        }
        for (Map.Entry<String, Double> e : outboundPct.entrySet()) {
            dataset.addValue(e.getValue(), "出站", e.getKey());
        }

        JFreeChart chart = ChartFactory.createBarChart(
                "TCP 控制位出现百分比", "控制位", "百分比 (%)", dataset,
                PlotOrientation.VERTICAL, true, true, false);

        return saveChart(chart, filename, 600, 400);
    }

    // ==================== 工具方法 ====================

    private String saveChart(JFreeChart chart, String filename, int width, int height)
            throws IOException {
        // 中文字体支持
        chart.getTitle().setFont(new Font("Microsoft YaHei", Font.BOLD, 16));
        if (chart.getLegend() != null) {
            chart.getLegend().setItemFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        }

        File file = new File(outputDir, filename);
        ChartUtils.saveChartAsPNG(file, chart, width, height);
        return file.getAbsolutePath();
    }
}
