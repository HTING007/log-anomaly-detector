package com.hting007.loganomaly;

import com.hting007.loganomaly.model.LogEvent;
import com.hting007.loganomaly.parse.SimpleAuthLogParser;
import picocli.CommandLine;

import java.io.BufferedReader;
import java.io.FileReader;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.Callable;

public class Main implements Callable<Integer> {

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

    @Override
    public Integer call() throws Exception {
        var parser = new SimpleAuthLogParser();

        int total = 0;
        int parsed = 0;
        int skipped = 0;

        try (BufferedReader br = new BufferedReader(new FileReader(input.toFile()))) {
            String line;
            while ((line = br.readLine()) != null) {
                total++;
                Optional<LogEvent> evt = parser.parseLine(line);
                if (evt.isPresent()) {
                    parsed++;
                    System.out.println(evt.get());
                } else {
                    skipped++;
                }
            }
        }

        System.out.printf("Done. total=%d parsed=%d skipped=%d%n", total, parsed, skipped);
        return 0;
    }

    public static void main(String[] args) {
        int code = new CommandLine(new Main()).execute(args);
        System.exit(code);
    }
}

