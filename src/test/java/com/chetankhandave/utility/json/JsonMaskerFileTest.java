package com.chetankhandave.utility.json;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * File-based tests for {@link JsonMasker}.
 *
 * <p>This class exercises the utility using realistic JSON documents stored
 * under {@code src/test/resources}. The test intentionally compares parsed
 * JSON trees rather than raw strings so differences in indentation, whitespace
 * or property formatting do not cause false failures.</p>
 */
public class JsonMaskerFileTest {

    private static final String INPUT_RESOURCE =
            "/json-masker/sample-input.json";
    private static final String EXPECTED_RESOURCE =
            "/json-masker/sample-expected-masked.json";

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    /**
     * Verifies the complete file-based masking flow:
     * <ol>
     *     <li>read the original JSON from a test-resource file,</li>
     *     <li>mask it using the reusable default configuration,</li>
     *     <li>read the expected masked JSON from another resource file, and</li>
     *     <li>compare both documents structurally.</li>
     * </ol>
     *
     * @throws Exception if a test resource cannot be read or parsed
     */
    @Test
    public void maskJson_inputFile_matchesExpectedMaskedFile() throws Exception {
        String inputJson = readResource(INPUT_RESOURCE);
        String expectedJson = readResource(EXPECTED_RESOURCE);

        String actualMaskedJson = JsonMasker.maskJson(inputJson);

        JsonNode expectedNode = OBJECT_MAPPER.readTree(expectedJson);
        JsonNode actualNode = OBJECT_MAPPER.readTree(actualMaskedJson);

        assertEquals(expectedNode, actualNode,
                "Masked JSON should structurally match the expected resource file");
    }

    /**
     * Verifies that file-based masking produces a new masked result while the
     * original JSON string read from the resource remains unchanged.
     *
     * @throws Exception if a test resource cannot be read or parsed
     */
    @Test
    public void maskJson_inputFile_originalJsonRemainsUnchanged() throws Exception {
        String inputJson = readResource(INPUT_RESOURCE);
        String originalSnapshot = inputJson;
        JsonNode originalNodeSnapshot = OBJECT_MAPPER.readTree(inputJson);

        String maskedJson = JsonMasker.maskJson(inputJson);

        assertEquals(originalSnapshot, inputJson,
                "JsonMasker must not modify the original input String");
        assertEquals(originalNodeSnapshot, OBJECT_MAPPER.readTree(inputJson),
                "Original JSON content must remain structurally unchanged");
        assertNotEquals(OBJECT_MAPPER.readTree(inputJson), OBJECT_MAPPER.readTree(maskedJson),
                "Masked JSON should be a different JSON representation when sensitive fields exist");
    }

    /**
     * Reads a UTF-8 classpath resource without relying on a physical file-system
     * path. This keeps the test portable across IDE, Maven and packaged test runs.
     *
     * @param resourcePath absolute classpath resource path
     * @return complete resource content as a UTF-8 string
     * @throws IOException if the resource is missing or cannot be read
     */
    static String readResource(String resourcePath) throws IOException {
        InputStream inputStream = JsonMaskerFileTest.class.getResourceAsStream(resourcePath);
        assertNotNull(inputStream, "Test resource not found: " + resourcePath);

        try (InputStream in = inputStream;
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        }
    }
}
