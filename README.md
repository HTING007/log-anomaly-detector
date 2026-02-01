## log-anomaly-detector

A Java 17 CLI tool that detects log anomaly spikes using window-based z-score aggregation.
It produces an explainable report in `text` or `json`, including top-K example log lines for each alert.

---

## Features

- Window-based anomaly detection using z-score over error counts
- Aggregation by `ip` or `user`
- Explainable alerts with `topK` example lines
- Output formats: human-readable `text` or machine-readable `json`
- Runnable fat JAR (Maven Shade) for easy execution
- Timezone support for local timestamps via `--tz` (IANA zone IDs)

---

## Requirements

- Java 17+
- Maven 3.9+ (or compatible)

---

## Build

```bash
mvn test
mvn clean package

