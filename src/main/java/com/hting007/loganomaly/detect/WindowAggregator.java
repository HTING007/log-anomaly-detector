package com.hting007.loganomaly.detect;

import com.hting007.loganomaly.model.LogEvent;

import java.time.Instant;
import java.util.*;

public class WindowAggregator {

    public record WindowKey(Instant windowStart, String key) {}

    private final int windowSeconds;

    public WindowAggregator(int windowSeconds) {
        if (windowSeconds <= 0) throw new IllegalArgumentException("windowSeconds must be > 0");
        this.windowSeconds = windowSeconds;
    }

    public Map<WindowKey, Integer> countFails(List<LogEvent> events, String mode) {
        // deterministic order for output/testing
        Map<WindowKey, Integer> counts = new TreeMap<>(Comparator
                .comparing((WindowKey wk) -> wk.windowStart())
                .thenComparing(wk -> wk.key()));

        String m = (mode == null) ? "ip" : mode.trim().toLowerCase();
        if (!m.equals("ip") && !m.equals("user")) {
            throw new IllegalArgumentException("mode must be 'ip' or 'user'");
        }

        for (LogEvent e : events) {
            if (e.success()) continue; // only FAIL contributes

            Instant ws = windowStart(e.timestamp());
            String k = m.equals("user") ? e.user() : e.ip();

            WindowKey wk = new WindowKey(ws, k);
            counts.put(wk, counts.getOrDefault(wk, 0) + 1);
        }

        return counts;
    }

    private Instant windowStart(Instant ts) {
        long epoch = ts.getEpochSecond();
        long start = (epoch / windowSeconds) * windowSeconds;
        return Instant.ofEpochSecond(start);
    }
}
