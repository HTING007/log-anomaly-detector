package com.hting007.loganomaly.detect;

import com.hting007.loganomaly.model.LogEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class WindowAggregatorTest {

    @Test
    void aggregatesFailsByIpPerWindow() {
        var agg = new WindowAggregator(60);

        var events = List.of(
                new LogEvent(Instant.parse("2026-01-28T10:30:01Z"), false, "alice", "1.2.3.4"),
                new LogEvent(Instant.parse("2026-01-28T10:30:05Z"), false, "alice", "1.2.3.4"),
                new LogEvent(Instant.parse("2026-01-28T10:30:10Z"), true,  "bob",   "8.8.8.8"), // OK ignored
                new LogEvent(Instant.parse("2026-01-28T10:31:01Z"), false, "alice", "1.2.3.4")
        );

        var counts = agg.countFails(events, "ip");

        assertEquals(2, counts.size());
        assertEquals(2, counts.get(new WindowAggregator.WindowKey(Instant.parse("2026-01-28T10:30:00Z"), "1.2.3.4")));
        assertEquals(1, counts.get(new WindowAggregator.WindowKey(Instant.parse("2026-01-28T10:31:00Z"), "1.2.3.4")));
    }

    @Test
    void rejectsInvalidMode() {
        var agg = new WindowAggregator(60);
        assertThrows(IllegalArgumentException.class, () -> agg.countFails(List.of(), "account"));
    }
}
