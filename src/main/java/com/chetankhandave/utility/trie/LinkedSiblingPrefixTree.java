package com.chetankhandave.utility.trie;

import java.util.Objects;

/**
 * Mutable, case-sensitive index of distinct strings with exact and prefix lookups.
 * Matching uses Java String semantics, including UTF-16 code units and no
 * Unicode normalization. Empty strings are valid keys. Instances require
 * external synchronization if shared across threads and modified.
 *
 * <p>Each node stores its first child and next sibling. Child lookup scans the
 * sibling list, taking O(d) time for a parent with d children. Traversal
 * takes O(L * D) worst-case time for L code units and maximum fan-out D.
 */
public final class LinkedSiblingPrefixTree {

    private final Node root = new Node('\0');
    private int size;

    /** Creates an empty prefix tree. */
    public LinkedSiblingPrefixTree() {
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
            char character = value.charAt(index);
            Node child = node.firstChild;
            Node lastSibling = null;
            while (child != null && child.character != character) {
                lastSibling = child;
                child = child.nextSibling;
            }
            if (child == null) {
                child = new Node(character);
                // Append the new child so siblings retain insertion order.
                if (lastSibling == null) {
                    node.firstChild = child;
                } else {
                    lastSibling.nextSibling = child;
                }
            }
            node = child;
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
     * Removes an exact key and prunes branches that no stored key uses.
     *
     * @param value string to remove
     * @return true if the key existed and was removed
     * @throws NullPointerException if value is null
     */
    public boolean remove(String value) {
        Objects.requireNonNull(value, "value");
        Node node = root;
        Node pruneParent = root;
        int pruneIndex = 0;

        for (int index = 0; index < value.length(); index++) {
            // A stored prefix or a sibling branch must survive the removal.
            if (node.terminal || (node.firstChild != null && node.firstChild.nextSibling != null)) {
                pruneParent = node;
                pruneIndex = index;
            }
            node = node.findChild(value.charAt(index));
            if (node == null) {
                return false;
            }
        }
        if (!node.terminal) {
            return false;
        }

        node.terminal = false;
        size--;
        if (node != root && node.firstChild == null) {
            pruneParent.unlinkChild(value.charAt(pruneIndex));
        }
        return true;
    }

    /**
     * Replaces a stored key with a different key. A successful replacement
     * leaves the number of stored keys unchanged.
     *
     * @param oldValue exact key to replace
     * @param newValue replacement key
     * @return true if replaced, or false if the old key is absent or the new
     *         key already exists (including an identical key)
     * @throws NullPointerException if either argument is null
     */
    public boolean replace(String oldValue, String newValue) {
        Objects.requireNonNull(oldValue, "oldValue");
        Objects.requireNonNull(newValue, "newValue");

        if (!contains(oldValue) || !add(newValue)) {
            return false;
        }
        remove(oldValue);
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
            node = node.findChild(value.charAt(index));
            if (node == null) {
                return null;
            }
        }
        return node;
    }

    private static final class Node {
        private final char character;
        private Node firstChild;
        private Node nextSibling;
        private boolean terminal;

        private Node(char character) {
            this.character = character;
        }

        private Node findChild(char character) {
            Node child = firstChild;
            while (child != null && child.character != character) {
                child = child.nextSibling;
            }
            return child;
        }

        // The caller has already traversed this edge, so the child exists.
        private void unlinkChild(char character) {
            Node previous = null;
            Node child = firstChild;
            while (child.character != character) {
                previous = child;
                child = child.nextSibling;
            }
            if (previous == null) {
                firstChild = child.nextSibling;
            } else {
                previous.nextSibling = child.nextSibling;
            }
        }
    }
}
