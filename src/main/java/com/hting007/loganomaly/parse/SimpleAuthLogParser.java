package com.yourname.loganomaly.parse;

import com.yourname.loganomaly.model.LogEvent;

import java.time.Instant;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SimpleAuthLogParser implements AuthLogParser {

    // Example:
    // 2026-01-28T10:30:01Z FAIL user=alice ip=1.2.3.4
    private static final Pattern P = Pattern.compile(
            "^(\\S+)\\s+(OK|FAIL)\\s+user=([^\\s]+)\\s+ip=([^\\s]+)\\s*$"
    );

    @Override
    public Optional<LogEvent> parseLine(String line) {
        if (line == null) return Optional.empty();

        Matcher m = P.matcher(line.trim());
        if (!m.matches()) return Optional.empty();

        try {
            Instant ts = Instant.parse(m.group(1));
            boolean success = m.group(2).equals("OK");
            String user = m.group(3);
            String ip = m.group(4);
            return Optional.of(new LogEvent(ts, success, user, ip));
        } catch (Exception e) {
            // Defensive: if timestamp parsing fails, don't crash
            return Optional.empty();
        }
    }
}

