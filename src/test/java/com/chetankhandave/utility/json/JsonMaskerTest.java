package com.chetankhandave.utility.json;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end and edge-case tests for JsonMasker.
 * <p>
 * These tests verify masking correctness, recursive traversal, custom/default
 * configuration behavior, invalid input handling and, critically, that source
 * JSON/JsonNode values are never mutated during masking.
 */
public class JsonMaskerTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private JsonNode toNode(String json) {
        try {
            return OBJECT_MAPPER.readTree(json);
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid test JSON", e);
        }
    }

    /** Verifies null input is returned as null. */
    @Test
    public void maskJson_nullInput_returnsNull() {
        assertNull(JsonMasker.maskJson(null));
    }

    /** Verifies blank JSON strings are returned unchanged. */
    @Test
    public void maskJson_blankInput_returnsOriginal() {
        assertEquals("", JsonMasker.maskJson(""));
        assertEquals("   ", JsonMasker.maskJson("   "));
        assertEquals("\n\t", JsonMasker.maskJson("\n\t"));
    }

    /** Verifies malformed JSON is returned unchanged rather than throwing. */
    @Test
    public void maskJson_invalidJson_returnsOriginal() {
        String input = "{ invalid-json }";
        assertEquals(input, JsonMasker.maskJson(input));
    }

    /** Verifies the default configuration applies all major masking styles. */
    @Test
    public void maskJson_defaultConfig_appliesConfiguredPolicies() {
        String input = "{"
                + "\"name\":\"chetan\","
                + "\"password\":\"abc123\","
                + "\"mobile\":\"9876543210\","
                + "\"accountNumber\":\"123456789012\","
                + "\"email\":\"chetan@example.com\","
                + "\"city\":\"Pune\""
                + "}";

        JsonNode output = toNode(JsonMasker.maskJson(input));

        assertEquals("c*e*a*", output.get("name").asText());
        assertEquals("****", output.get("password").asText());
        assertEquals("******3210", output.get("mobile").asText());
        assertEquals("********9012", output.get("accountNumber").asText());
        assertEquals("che***************", output.get("email").asText());
        assertEquals("Pune", output.get("city").asText());
    }

    /** Verifies key matching is case-insensitive. */
    @Test
    public void maskJson_caseInsensitiveKeys_areMasked() {
        String input = "{\"PASSWORD\":\"abc\",\"Mobile\":\"9876543210\",\"EMAIL\":\"chetan@example.com\"}";
        JsonNode output = toNode(JsonMasker.maskJson(input));

        assertEquals("****", output.get("PASSWORD").asText());
        assertEquals("******3210", output.get("Mobile").asText());
        assertEquals("che***************", output.get("EMAIL").asText());
    }

    /** Verifies fields not configured for masking keep their original type and value. */
    @Test
    public void maskJson_unconfiguredFields_remainUnchanged() {
        String input = "{\"city\":\"Pune\",\"age\":35,\"active\":true}";
        JsonNode output = toNode(JsonMasker.maskJson(input));

        assertEquals("Pune", output.get("city").asText());
        assertEquals(35, output.get("age").asInt());
        assertTrue(output.get("active").asBoolean());
    }

    /** Verifies JSON null values remain JSON null after masking. */
    @Test
    public void maskJson_nullValues_remainNull() {
        String input = "{\"password\":null,\"mobile\":null,\"name\":null}";
        JsonNode output = toNode(JsonMasker.maskJson(input));

        assertTrue(output.get("password").isNull());
        assertTrue(output.get("mobile").isNull());
        assertTrue(output.get("name").isNull());
    }

    /** Verifies numeric sensitive values can be masked using their textual representation. */
    @Test
    public void maskJson_numericSensitiveValue_isMasked() {
        String input = "{\"mobile\":9876543210,\"pin\":1234}";
        JsonNode output = toNode(JsonMasker.maskJson(input));

        assertEquals("******3210", output.get("mobile").asText());
        assertEquals("****", output.get("pin").asText());
    }

    /** Verifies nested objects are traversed recursively. */
    @Test
    public void maskJson_nestedObjects_areMaskedRecursively() {
        String input = "{"
                + "\"customer\":{"
                + "\"name\":\"chetan\","
                + "\"mobile\":\"9876543210\","
                + "\"address\":{\"city\":\"Pune\",\"otp\":\"123456\"}"
                + "}"
                + "}";

        JsonNode output = toNode(JsonMasker.maskJson(input));

        assertEquals("c*e*a*", output.get("customer").get("name").asText());
        assertEquals("******3210", output.get("customer").get("mobile").asText());
        assertEquals("Pune", output.get("customer").get("address").get("city").asText());
        assertEquals("****", output.get("customer").get("address").get("otp").asText());
    }

    /** Verifies arrays containing objects are traversed recursively. */
    @Test
    public void maskJson_arrayObjects_areMaskedRecursively() {
        String input = "{\"users\":["
                + "{\"name\":\"chetan\",\"mobile\":\"9876543210\"},"
                + "{\"name\":\"rahul\",\"mobile\":\"1234567890\"}]}";

        JsonNode output = toNode(JsonMasker.maskJson(input));

        assertEquals("c*e*a*", output.get("users").get(0).get("name").asText());
        assertEquals("******3210", output.get("users").get(0).get("mobile").asText());
        assertEquals("r*h*l", output.get("users").get(1).get("name").asText());
        assertEquals("******7890", output.get("users").get(1).get("mobile").asText());
    }

    /** Verifies a JSON array can itself be the root document. */
    @Test
    public void maskJson_rootArray_isSupported() {
        JsonNode output = toNode(JsonMasker.maskJson("[{\"password\":\"abc\"},{\"mobile\":\"9876543210\"}]"));

        assertTrue(output.isArray());
        assertEquals("****", output.get(0).get("password").asText());
        assertEquals("******3210", output.get(1).get("mobile").asText());
    }

    /** Verifies a custom configuration is honored and does not implicitly merge default rules. */
    @Test
    public void maskJson_customConfig_appliesOnlyCustomRules() {
        JsonMaskingConfig config = JsonMaskingConfig.builder()
                .completeMask("city")
                .alternateMask("code")
                .keepLast("amount", 2)
                .keepFirst("status", 3)
                .build();

        String input = "{\"city\":\"Pune\",\"code\":\"ABCDEF\",\"amount\":123456,"
                + "\"status\":\"SUCCESS\",\"password\":\"abc\"}";
        JsonNode output = toNode(JsonMasker.maskJson(input, config));

        assertEquals("****", output.get("city").asText());
        assertEquals("A*C*E*", output.get("code").asText());
        assertEquals("****56", output.get("amount").asText());
        assertEquals("SUC****", output.get("status").asText());
        assertEquals("abc", output.get("password").asText());
    }

    /** Verifies a null custom configuration falls back to default configuration. */
    @Test
    public void maskJson_nullConfig_usesDefaultConfig() {
        JsonNode output = toNode(JsonMasker.maskJson("{\"password\":\"abc\"}", null));
        assertEquals("****", output.get("password").asText());
    }

    /** Verifies the original String reference/content is untouched by masking. */
    @Test
    public void maskJson_originalStringRemainsUnchanged() {
        String original = "{\"password\":\"abc123\",\"name\":\"chetan\"}";
        String beforeMasking = original;

        String masked = JsonMasker.maskJson(original);

        assertSame(beforeMasking, original);
        assertEquals("{\"password\":\"abc123\",\"name\":\"chetan\"}", original);
        assertNotEquals(original, masked);
        assertEquals("****", toNode(masked).get("password").asText());
    }

    /**
     * Critical immutability scenario: verifies masking a mutable ObjectNode returns a new tree
     * while the original tree, including nested values, remains unchanged.
     */
    @Test
    public void maskNode_originalObjectTreeRemainsUnchanged() throws Exception {
        ObjectNode original = (ObjectNode) OBJECT_MAPPER.readTree(
                "{\"password\":\"abc\",\"customer\":{\"name\":\"chetan\",\"mobile\":\"9876543210\"}}"
        );
        String originalSnapshot = OBJECT_MAPPER.writeValueAsString(original);

        JsonNode masked = JsonMasker.maskNode(original, JsonMaskingConfig.defaultConfig());

        assertEquals(originalSnapshot, OBJECT_MAPPER.writeValueAsString(original));
        assertEquals("abc", original.get("password").asText());
        assertEquals("chetan", original.get("customer").get("name").asText());
        assertEquals("9876543210", original.get("customer").get("mobile").asText());
        assertEquals("****", masked.get("password").asText());
        assertEquals("c*e*a*", masked.get("customer").get("name").asText());
        assertNotSame(original, masked);
    }

    /** Verifies arrays are also deep-copied and source arrays remain unchanged. */
    @Test
    public void maskArrayNode_originalArrayRemainsUnchanged() throws Exception {
        ArrayNode original = (ArrayNode) OBJECT_MAPPER.readTree("[{\"password\":\"abc\"}]");
        String originalSnapshot = OBJECT_MAPPER.writeValueAsString(original);

        JsonNode masked = JsonMasker.maskArrayNode(original, JsonMaskingConfig.defaultConfig());

        assertEquals(originalSnapshot, OBJECT_MAPPER.writeValueAsString(original));
        assertEquals("abc", original.get(0).get("password").asText());
        assertEquals("****", masked.get(0).get("password").asText());
        assertNotSame(original, masked);
    }

    /** Verifies null node handling for direct JsonNode API users. */
    @Test
    public void maskNode_nullInput_returnsNull() {
        assertNull(JsonMasker.maskNode(null, JsonMaskingConfig.defaultConfig()));
    }

    /** Verifies a primitive root node is copied and not arbitrarily masked without a field policy. */
    @Test
    public void maskNode_primitiveRoot_returnsEquivalentValue() throws Exception {
        JsonNode input = OBJECT_MAPPER.readTree("\"hello\"");
        JsonNode output = JsonMasker.maskNode(input, JsonMaskingConfig.defaultConfig());

        assertEquals("hello", output.asText());
    }

    /** Verifies null ObjectNode input is handled safely. */
    @Test
    public void maskObjectNode_nullInput_returnsNull() {
        assertNull(JsonMasker.maskObjectNode(null, JsonMaskingConfig.defaultConfig()));
    }

    /** Verifies null ArrayNode input is handled safely. */
    @Test
    public void maskArrayNode_nullInput_returnsNull() {
        assertNull(JsonMasker.maskArrayNode(null, JsonMaskingConfig.defaultConfig()));
    }

    /** Verifies the package-visible parser succeeds for valid JSON. */
    @Test
    public void parseJson_validJson_returnsNode() throws Exception {
        JsonNode node = JsonMasker.parseJson("{\"name\":\"chetan\"}");
        assertEquals("chetan", node.get("name").asText());
    }

    /** Verifies the package-visible parser exposes IOException for invalid JSON. */
    @Test
    public void parseJson_invalidJson_throwsIOException() {
        assertThrows(IOException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                JsonMasker.parseJson("{ invalid-json }");
            }
        });
    }

    /** Verifies JsonNode serialization produces JSON text. */
    @Test
    public void toJsonString_validNode_returnsJsonText() throws Exception {
        JsonNode node = OBJECT_MAPPER.readTree("{\"name\":\"chetan\"}");
        assertEquals("{\"name\":\"chetan\"}", JsonMasker.toJsonString(node));
    }
}
