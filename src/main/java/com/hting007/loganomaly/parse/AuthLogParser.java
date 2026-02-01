package com.hting007.loganomaly.parse;

import com.hting007.loganomaly.model.LogEvent;

import java.util.Optional;

public interface AuthLogParser {
    Optional<LogEvent> parseLine(String line);
}

