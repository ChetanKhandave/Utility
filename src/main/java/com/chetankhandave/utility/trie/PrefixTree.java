package com.chetankhandave.utility.trie;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Mutable, case-sensitive index of distinct strings with exact and prefix lookups.
 * Matching uses Java String semantics, including UTF-16 code units and no
 * Unicode normalization. Empty strings are valid keys. Instances require
 * external synchronization if shared across threads and modified.
 *
 * <p>Operations that traverse a key take expected O(L) time, where L is the
 * number of UTF-16 code units examined. Keys share storage for common prefixes.
 */
public final class PrefixTree {

    private final Node root = new Node();
    private int size;

    /** Creates an empty prefix tree. */
    public PrefixTree() {
    }

    /**
     * Adds a string to the tree.
     *
     * @param value string to store
     * @return true if the string was added, or false if it already existed
     * @throws NullPointerException if value is null
     */
    public boolean add(String value) {
        Objects.requireNonNull(value, "value");
        Node node = root;
        for (int index = 0; index < value.length(); index++) {
            node = node.children.computeIfAbsent(value.charAt(index), key -> new Node());
        }
        if (node.terminal) {
            return false;
        }
        // A node can mark a complete key and still have children.
        node.terminal = true;
        size++;
        return true;
    }

    /**
     * Checks whether the complete string is stored.
     *
     * @param value string to find
     * @return true if the exact string exists
     * @throws NullPointerException if value is null
     */
    public boolean contains(String value) {
        Node node = findNode(Objects.requireNonNull(value, "value"));
        return node != null && node.terminal;
    }

    /**
     * Checks whether at least one stored string starts with the given prefix.
     *
     * @param prefix prefix to find, which may be empty
     * @return true if a stored string starts with prefix
     * @throws NullPointerException if prefix is null
     */
    public boolean startsWith(String prefix) {
        Objects.requireNonNull(prefix, "prefix");
        return size > 0 && findNode(prefix) != null;
    }

    /**
     * Returns the number of distinct strings stored in the tree.
     *
     * @return number of stored strings
     */
    public int size() {
        return size;
    }

    private Node findNode(String value) {
        Node node = root;
        for (int index = 0; index < value.length(); index++) {
            node = node.children.get(value.charAt(index));
            if (node == null) {
                return null;
            }
        }
        return node;
    }

    private static final class Node {
        private final Map<Character, Node> children = new HashMap<>();
        private boolean terminal;
    }
}
