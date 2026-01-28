package com.yourname.loganomaly.parse;

import com.yourname.loganomaly.model.LogEvent;

import java.util.Optional;

public interface AuthLogParser {
    Optional<LogEvent> parseLine(String line);
}

