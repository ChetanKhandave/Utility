package com.chetankhandave.utility.certificate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Objects;

/** UTF-8 output adapter; refuses to overwrite any existing file, including a source keystore. */
public final class ComparisonReportWriter {
    public void write(Path output, KeyStoreComparison comparison, ComparisonReportFormatter formatter)
            throws IOException {
        Objects.requireNonNull(output,"output");
        Objects.requireNonNull(comparison,"comparison");
        Objects.requireNonNull(formatter,"formatter");
        // Render first: formatter errors must not leave an empty output file.
        byte[] contents=formatter.format(comparison).getBytes(StandardCharsets.UTF_8);
        Files.write(output,contents,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE);
    }
}
