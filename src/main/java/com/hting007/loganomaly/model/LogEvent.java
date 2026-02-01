package com.hting007.loganomaly.model;

import java.time.Instant;

public record LogEvent(
        Instant timestamp,
        boolean success,
        String user,
        String ip
) {}
