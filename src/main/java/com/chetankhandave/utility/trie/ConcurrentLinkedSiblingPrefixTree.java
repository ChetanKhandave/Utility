package com.chetankhandave.utility.trie;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Logger;
import java.util.function.Supplier;

/**
 * Thread-safe linked-sibling trie. Reads may overlap, and each update holds
 * exclusive access for its entire duration. Separate calls can observe
 * different states if a writer runs between them.
 *
 * <p>Matching is case-sensitive. Empty strings are valid keys.
 * Enable JUL FINEST logging for operation completion messages.
 */
public final class ConcurrentLinkedSiblingPrefixTree {

    private static final Logger LOGGER =
            Logger.getLogger(ConcurrentLinkedSiblingPrefixTree.class.getName());

    private final LinkedSiblingPrefixTree tree = new LinkedSiblingPrefixTree();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    /** Creates an empty concurrent trie. */
    public ConcurrentLinkedSiblingPrefixTree() {
    }

    /**
     * Adds a key.
     *
     * @param value key to add
     * @return true if the key was absent
     * @throws NullPointerException if a string argument is null
     */
    public boolean add(String value) {
        return execute(lock.writeLock(), "add", () -> tree.add(value));
    }

    /**
     * Removes an exact key.
     *
     * @param value key to remove
     * @return true if the key was present
     * @throws NullPointerException if a string argument is null
     */
    public boolean remove(String value) {
        return execute(lock.writeLock(), "remove", () -> tree.remove(value));
    }

    /**
     * Atomically replaces a stored key.
     *
     * @param oldValue exact key to replace
     * @param newValue replacement key
     * @return true if the old key existed and the new key was absent
     * @throws NullPointerException if a string argument is null
     */
    public boolean replace(String oldValue, String newValue) {
        return execute(lock.writeLock(), "replace", () -> tree.replace(oldValue, newValue));
    }

    /**
     * Checks for an exact key.
     *
     * @param value key to find
     * @return true if the key exists
     * @throws NullPointerException if a string argument is null
     */
    public boolean contains(String value) {
        return execute(lock.readLock(), "contains", () -> tree.contains(value));
    }

    /**
     * Checks whether any stored key starts with a prefix.
     *
     * @param prefix prefix to find
     * @return true if at least one key matches
     * @throws NullPointerException if a string argument is null
     */
    public boolean startsWith(String prefix) {
        return execute(lock.readLock(), "startsWith", () -> tree.startsWith(prefix));
    }

    /**
     * Counts the distinct keys.
     *
     * @return number of stored keys
     */
    public int size() {
        return execute(lock.readLock(), "size", () -> tree.size());
    }

    private <T> T execute(Lock operationLock, String operation, Supplier<T> action) {
        T result;
        operationLock.lock();
        try {
            result = action.get();
        } finally {
            operationLock.unlock();
        }
        // Logging handlers run outside the lock and receive no key data.
        LOGGER.finest(operation);
        return result;
    }
}
