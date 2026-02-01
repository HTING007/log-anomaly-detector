package com.hting007.loganomaly;

import com.hting007.loganomaly.parse.SimpleAuthLogParser;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class SimpleAuthLogParserTest {

    @Test
    void parsesValidLine() {
        var p = new SimpleAuthLogParser();
        var evt = p.parseLine("2026-01-28T10:30:01Z FAIL user=alice ip=1.2.3.4");
        assertTrue(evt.isPresent());
        assertFalse(evt.get().success());
        assertEquals("alice", evt.get().user());
        assertEquals("1.2.3.4", evt.get().ip());
    }

    @Test
    void skipsBadLineWithoutCrashing() {
        var p = new SimpleAuthLogParser();
        var evt = p.parseLine("bad_line_that_should_not_crash");
        assertTrue(evt.isEmpty());
    }
}

