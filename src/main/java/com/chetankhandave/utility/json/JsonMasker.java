package com.chetankhandave.utility.json;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Thread-safe utility for masking sensitive values in arbitrary JSON structures.
 * <p>
 * The utility never mutates the original JSON String or the supplied JsonNode tree.
 * It always creates and returns a new masked representation.
 */
public final class JsonMasker {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final MaskingStrategy DEFAULT_STRATEGY = new DefaultMaskingStrategy();

    private JsonMasker() {
        throw new AssertionError("Utility class must not be instantiated");
    }

    /**
     * Masks JSON using the reusable default configuration.
     *
     * @param json input JSON string
     * @return a new masked JSON string; null when input is null; original string when parsing fails
     */
    public static String maskJson(String json) {
        return maskJson(json, JsonMaskingConfig.defaultConfig());
    }

    /**
     * Masks JSON using a caller-supplied configuration.
     * A null configuration falls back to the default configuration.
     *
     * @param json input JSON string
     * @param config masking configuration
     * @return a new masked JSON string; null when input is null; original string when parsing fails
     */
    public static String maskJson(String json, JsonMaskingConfig config) {
        if (json == null) {
            return null;
        }
        if (json.trim().isEmpty()) {
            return json;
        }

        try {
            JsonNode root = parseJson(json);
            JsonNode maskedNode = maskNode(root, config);
            return toJsonString(maskedNode);
        } catch (IOException e) {
            return json;
        }
    }

    /**
     * Parses JSON into a JsonNode. Exposed package-wide for focused unit testing.
     */
    static JsonNode parseJson(String json) throws IOException {
        return OBJECT_MAPPER.readTree(json);
    }

    /**
     * Serializes a JsonNode into JSON text. Exposed package-wide for focused unit testing.
     */
    static String toJsonString(JsonNode node) throws JsonProcessingException {
        return OBJECT_MAPPER.writeValueAsString(node);
    }

    /**
     * Masks a JsonNode without mutating the supplied node.
     */
    public static JsonNode maskNode(JsonNode node, JsonMaskingConfig config) {
        if (node == null || node.isNull()) {
            return node;
        }

        JsonMaskingConfig actualConfig = config == null
                ? JsonMaskingConfig.defaultConfig()
                : config;

        if (node.isObject()) {
            return maskObjectNode((ObjectNode) node, actualConfig);
        }
        if (node.isArray()) {
            return maskArrayNode((ArrayNode) node, actualConfig);
        }
        return node.deepCopy();
    }

    /**
     * Masks an object node recursively while preserving the supplied object unchanged.
     */
    public static JsonNode maskObjectNode(ObjectNode objectNode, JsonMaskingConfig config) {
        if (objectNode == null) {
            return null;
        }

        JsonMaskingConfig actualConfig = config == null
                ? JsonMaskingConfig.defaultConfig()
                : config;
        ObjectNode copiedObject = objectNode.deepCopy();

        List<String> fieldNames = new ArrayList<String>();
        Iterator<String> iterator = copiedObject.fieldNames();
        while (iterator.hasNext()) {
            fieldNames.add(iterator.next());
        }

        for (String fieldName : fieldNames) {
            JsonNode childNode = copiedObject.get(fieldName);
            MaskingPolicy policy = actualConfig.getPolicy(fieldName);

            if (policy.getMaskingType() == MaskingType.NONE) {
                copiedObject.set(fieldName, maskNode(childNode, actualConfig));
            } else {
                copiedObject.set(fieldName, maskValueNode(childNode, policy, actualConfig));
            }
        }
        return copiedObject;
    }

    /**
     * Masks each element of an array recursively without mutating the supplied array.
     */
    public static JsonNode maskArrayNode(ArrayNode arrayNode, JsonMaskingConfig config) {
        if (arrayNode == null) {
            return null;
        }

        JsonMaskingConfig actualConfig = config == null
                ? JsonMaskingConfig.defaultConfig()
                : config;
        ArrayNode copiedArray = arrayNode.deepCopy();

        for (int i = 0; i < copiedArray.size(); i++) {
            copiedArray.set(i, maskNode(copiedArray.get(i), actualConfig));
        }
        return copiedArray;
    }

    /**
     * Masks one configured JSON value. Container values are processed recursively;
     * scalar values are delegated to the masking strategy.
     */
    public static JsonNode maskValueNode(JsonNode node,
                                         MaskingPolicy policy,
                                         JsonMaskingConfig config) {
        if (node == null || node.isNull()) {
            return node;
        }

        JsonMaskingConfig actualConfig = config == null
                ? JsonMaskingConfig.defaultConfig()
                : config;

        if (node.isObject() || node.isArray()) {
            return maskNode(node, actualConfig);
        }

        String maskedValue = DEFAULT_STRATEGY.mask(node.asText(), policy);
        return OBJECT_MAPPER.getNodeFactory().textNode(maskedValue);
    }
}
