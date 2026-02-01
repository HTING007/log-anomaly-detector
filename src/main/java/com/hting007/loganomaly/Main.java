package com.hting007.loganomaly;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.hting007.loganomaly.parse.SimpleAuthLogParser;
import picocli.CommandLine;

import java.io.BufferedReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@CommandLine.Command(
        name = "log-anomaly-detector",
        mixinStandardHelpOptions = true,
        version = "1.0.0",
        description = "Detects log anomalies using window-based z-score aggregation and outputs a report."
)
public class Main implements Callable<Integer> {

    @CommandLine.Option(
        names = {"--tz"},
        description = "IANA time zone for local timestamps (default: system zone)"
    )
    private String timeZoneId;

    @CommandLine.Option(names = {"-i", "--input"}, required = true, description = "Path to log file")
    private Path input;

    @CommandLine.Option(
            names = {"-w", "--window"},
            description = "Window size in seconds (default: ${DEFAULT-VALUE})"
    )
    private int windowSeconds = 60;

    @CommandLine.Option(
            names = {"-z", "--zscore"},
            description = "Z-score threshold for alerts (default: ${DEFAULT-VALUE})"
    )
    private double zThreshold = 3.0;

    @CommandLine.Option(
            names = {"-k", "--key"},
            description = "Aggregation key: ip or user (default: ${DEFAULT-VALUE})"
    )
    private String key = "ip";

    @CommandLine.Option(
            names = {"-o", "--output"},
            description = "Output file path (default: stdout)"
    )
    private Path output;

    @CommandLine.Option(
            names = {"--format"},
            description = "Output format: text or json (default: ${DEFAULT-VALUE})"
    )
    private String format = "text";

    @CommandLine.Option(
            names = {"--topk"},
            description = "Max examples stored per alert (default: ${DEFAULT-VALUE})"
    )
    private int topK = 5;

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final Pattern USER_PAT = Pattern.compile("\\buser=([^\\s]+)");
    private static final Pattern IP_PAT = Pattern.compile("\\bip=([^\\s]+)");

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    @Override
    public Integer call() throws Exception {
        // basic validation
        if (!Files.exists(input) || !Files.isRegularFile(input)) {
            System.err.println("ERROR: input file not found: " + input);
            return 2;
        }
        if (windowSeconds < 1) {
            System.err.println("ERROR: --window must be >= 1");
            return 2;
        }
        if (topK < 1) {
            System.err.println("ERROR: --topk must be >= 1");
            return 2;
        }
        if (!key.equals("ip") && !key.equals("user")) {
            System.err.println("ERROR: --key must be 'ip' or 'user'");
            return 2;
        }
        if (!format.equals("text") && !format.equals("json")) {
            System.err.println("ERROR: --format must be 'text' or 'json'");
            return 2;
        }

        // keep your parser (still useful for parsed/skipped counts)
        var parser = new SimpleAuthLogParser();

        long total = 0;
        long parsed = 0;
        long skipped = 0;

        // counts[keyValue][windowStartEpochSec] = count
        Map<String, Map<Long, Integer>> counts = new HashMap<>();
        // examples[keyValue][windowStartEpochSec] = list of lines (topK)
        Map<String, Map<Long, List<String>>> examples = new HashMap<>();

        try (BufferedReader br = Files.newBufferedReader(input)) {
            String line;
            while ((line = br.readLine()) != null) {
                total++;

                // maintain your parse stats
                if (parser.parseLine(line).isPresent()) parsed++;
                else skipped++;

                // only count "error-ish" lines for spikes
                if (!isErrorish(line)) continue;

                Long t = tryParseEpochSeconds(line);
                if (t == null) continue; // no timestamp -> can't bucket

                long windowStart = (t / windowSeconds) * windowSeconds;
                String keyValue = extractKeyValue(line, key);

                counts.computeIfAbsent(keyValue, k -> new HashMap<>());
                examples.computeIfAbsent(keyValue, k -> new HashMap<>());

                counts.get(keyValue).merge(windowStart, 1, Integer::sum);

                // store examples (topK)
                examples.get(keyValue).computeIfAbsent(windowStart, w -> new ArrayList<>());
                List<String> exList = examples.get(keyValue).get(windowStart);
                if (exList.size() < topK) exList.add(line);
            }
        }

        // Build alerts: for each keyValue, compute mean/std across windows and flag zscore spikes
        List<Map<String, Object>> alerts = new ArrayList<>();

        ZoneId zid;
        try {
            zid = (timeZoneId == null || timeZoneId.isBlank())
                    ? ZoneId.systemDefault()
                    : ZoneId.of(timeZoneId);
        } catch (Exception e) {
            System.err.println("ERROR: invalid --tz value: " + timeZoneId);
            return 2;
        }

        for (var entry : counts.entrySet()) {
            String keyValue = entry.getKey();
            Map<Long, Integer> perWindow = entry.getValue();

            // sort windows for stable output
            List<Long> windows = new ArrayList<>(perWindow.keySet());
            Collections.sort(windows);

            List<Integer> series = new ArrayList<>();
            for (Long w : windows) series.add(perWindow.get(w));

            double mean = mean(series);
            double std = stddev(series, mean);

            for (Long w : windows) {
                int c = perWindow.get(w);
                double z = (std > 0.0) ? (c - mean) / std : 0.0;

                if (std > 0.0 && z >= zThreshold) {
                    Map<String, Object> alert = new LinkedHashMap<>();

                    Instant ws = Instant.ofEpochSecond(w);
                    Instant we = Instant.ofEpochSecond(w + windowSeconds);

                    alert.put("type", "error_spike_zscore");
                    alert.put("key", key);
                    alert.put("keyValue", keyValue);

                    // keep original (UTC) fields
                    alert.put("windowStart", ws);
                    alert.put("windowEnd", we);

                    // add clearer fields
                    alert.put("windowStartUtc", ws);
                    alert.put("windowEndUtc", we);
                    alert.put("windowStartLocal", ws.atZone(zid).toString());
                    alert.put("windowEndLocal", we.atZone(zid).toString());


                    alert.put("count", c);
                    alert.put("zscore", round2(z));
                    alert.put("examples", examples.getOrDefault(keyValue, Map.of())
                            .getOrDefault(w, List.of()));

                    alerts.add(alert);
                }
            }
        }

        // Sort alerts by count desc, then zscore desc
        alerts.sort((a, b) -> {
            int c1 = (int) a.get("count");
            int c2 = (int) b.get("count");
            if (c1 != c2) return Integer.compare(c2, c1);
            double z1 = (double) a.get("zscore");
            double z2 = (double) b.get("zscore");
            return Double.compare(z2, z1);
        });

        Map<String, Object> report = new LinkedHashMap<>();
        report.put("tool", "log-anomaly-detector");
        report.put("analysedAt", Instant.now());
        report.put("input", input.toString());

        Map<String, Object> cfg = new LinkedHashMap<>();
        cfg.put("key", key);
        cfg.put("windowSeconds", windowSeconds);
        cfg.put("zThreshold", zThreshold);
        cfg.put("topK", topK);
        cfg.put("format", format);
        report.put("config", cfg);

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("totalLines", total);
        summary.put("parsedLines", parsed);
        summary.put("skippedLines", skipped);
        summary.put("alerts", alerts.size());
        report.put("summary", summary);

        report.put("alerts", alerts);

        String out;
        if (format.equals("json")) {
            out = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(report);
        } else {
            out = toTextReport(report);
        }

        if (output == null) {
            System.out.println(out);
        } else {
            Files.writeString(output, out);
        }

        return 0;
    }

    private static boolean isErrorish(String line) {
        if (line == null) return false;
        // tune later if needed
        return line.contains(" ERROR ") || line.startsWith("ERROR")
                || line.toLowerCase().contains("failed")
                || line.toLowerCase().contains("timeout")
                || line.contains("Exception");
    }

    private static String extractKeyValue(String line, String key) {
        Pattern p = key.equals("user") ? USER_PAT : IP_PAT;
        Matcher m = p.matcher(line);
        if (m.find()) return m.group(1);
        return "unknown";
    }

    private static Long tryParseEpochSeconds(String line) {
        // expects prefix like: "2026-02-01 10:00:02 ..."
        if (line == null || line.length() < 19) return null;
        String prefix = line.substring(0, 19);
        try {
            LocalDateTime ldt = LocalDateTime.parse(prefix, TS);
            return ldt.atZone(ZoneId.systemDefault()).toEpochSecond();
        } catch (Exception ignored) {
            return null;
        }
    }

    private static double mean(List<Integer> xs) {
        if (xs.isEmpty()) return 0.0;
        double sum = 0.0;
        for (int x : xs) sum += x;
        return sum / xs.size();
    }

    private static double stddev(List<Integer> xs, double mean) {
        if (xs.size() < 2) return 0.0;
        double s = 0.0;
        for (int x : xs) {
            double d = x - mean;
            s += d * d;
        }
        return Math.sqrt(s / xs.size());
    }

    private static double round2(double x) {
        return Math.round(x * 100.0) / 100.0;
    }

    private static String toTextReport(Map<String, Object> report) {
        @SuppressWarnings("unchecked")
        Map<String, Object> summary = (Map<String, Object>) report.get("summary");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> alerts = (List<Map<String, Object>>) report.get("alerts");
        @SuppressWarnings("unchecked")
        Map<String, Object> cfg = (Map<String, Object>) report.get("config");

        StringBuilder sb = new StringBuilder();
        sb.append("log-anomaly-detector report\n");
        sb.append("input: ").append(report.get("input")).append("\n");
        sb.append("analysedAt: ").append(report.get("analysedAt")).append("\n");
        sb.append("config: key=").append(cfg.get("key"))
                .append(" windowSeconds=").append(cfg.get("windowSeconds"))
                .append(" zThreshold=").append(cfg.get("zThreshold"))
                .append("\n");
        sb.append("summary: totalLines=").append(summary.get("totalLines"))
                .append(" parsedLines=").append(summary.get("parsedLines"))
                .append(" skippedLines=").append(summary.get("skippedLines"))
                .append(" alerts=").append(summary.get("alerts"))
                .append("\n");

        if (alerts.isEmpty()) {
            sb.append("alerts: none\n");
            return sb.toString();
        }

        sb.append("alerts:\n");
        for (var a : alerts) {
            sb.append("- type=").append(a.get("type"))
                    .append(" key=").append(a.get("key"))
                    .append(" keyValue=").append(a.get("keyValue"))
                    .append(" windowStart=").append(a.get("windowStart"))
                    .append(" count=").append(a.get("count"))
                    .append(" zscore=").append(a.get("zscore"))
                    .append("\n");
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        int code = new CommandLine(new Main()).execute(args);
        System.exit(code);
    }
}
