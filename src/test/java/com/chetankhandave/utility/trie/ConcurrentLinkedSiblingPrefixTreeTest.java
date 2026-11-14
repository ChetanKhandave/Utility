package com.chetankhandave.utility.trie;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Callable;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Verifies the public contract and sibling pruning of the linked trie. */
class ConcurrentLinkedSiblingPrefixTreeTest {

    private final ConcurrentLinkedSiblingPrefixTree tree = new ConcurrentLinkedSiblingPrefixTree();

    /** Checks lookup and size before any key is inserted. */
    @Test
    void emptyTreeHasNoKeysOrPrefixes() {
        assertEquals(0, tree.size());
        assertFalse(tree.contains(""));
        assertFalse(tree.contains("emp"));
        assertFalse(tree.startsWith(""));
        assertFalse(tree.startsWith("emp"));
    }

    /** Checks exact and prefix lookup along shared paths and absent branches. */
    @Test
    void exactLookupDistinguishesPrefixesAndMissingBranches() {
        assertTrue(tree.add("employee"));
        assertTrue(tree.add("employer"));
        assertTrue(tree.startsWith("employ"));
        assertFalse(tree.contains("employ"));
        assertFalse(tree.startsWith("employx"));
        assertFalse(tree.contains("employee1"));
        assertTrue(tree.add("employ"));
        assertTrue(tree.contains("employ"));
        assertTrue(tree.contains("employee"));
        assertTrue(tree.contains("employer"));
        assertTrue(tree.startsWith("employee"));
        assertEquals(3, tree.size());
    }

    /** Checks that extending a stored prefix and adding a duplicate preserve the key count. */
    @Test
    void longerKeyPreservesExistingShorterKeyAndDuplicateDoesNotChangeSize() {
        assertTrue(tree.add("emp"));
        assertTrue(tree.add("employee"));
        assertFalse(tree.add(new String("emp")));
        assertTrue(tree.contains("emp"));
        assertEquals(2, tree.size());
    }

    /** Checks that the empty string has its own terminal flag at the root. */
    @Test
    void emptyStringIsAnIndependentKey() {
        assertTrue(tree.add("emp"));
        assertTrue(tree.startsWith(""));
        assertFalse(tree.contains(""));
        assertTrue(tree.add(""));
        assertFalse(tree.add(""));
        assertTrue(tree.contains(""));
        assertEquals(2, tree.size());
    }

    /** Checks that null inputs are rejected before the tree is changed. */
    @Test
    void nullIsRejectedWithoutChangingTree() {
        assertThrows(NullPointerException.class, () -> tree.add(null));
        assertThrows(NullPointerException.class, () -> tree.contains(null));
        assertThrows(NullPointerException.class, () -> tree.startsWith(null));
        assertEquals(0, tree.size());
    }

    /** Checks case, whitespace, and distinct UTF-16 representations. */
    @Test
    void matchingPreservesCaseWhitespaceAndUnicodeRepresentation() {
        assertTrue(tree.add(" Chetan "));
        assertTrue(tree.add("caf\u00e9\ud83d\ude00"));
        assertFalse(tree.contains("Chetan"));
        assertFalse(tree.contains(" chetan "));
        assertFalse(tree.contains("cafe\u0301\ud83d\ude00"));
        assertTrue(tree.contains("caf\u00e9\ud83d\ude00"));
        assertTrue(tree.startsWith("caf\u00e9"));
    }

    /** Checks that long paths can be traversed without recursive calls. */
    @Test
    void handlesLongKeysIteratively() {
        char[] characters = new char[20_000];
        Arrays.fill(characters, 'a');
        String key = new String(characters);
        assertTrue(tree.add(key));
        assertTrue(tree.contains(key));
        assertTrue(tree.startsWith(key.substring(0, key.length() - 1)));
        assertFalse(tree.contains(key + "a"));
    }

    /** Checks that separate trees have independent roots and key counts. */
    @Test
    void instancesMaintainIndependentState() {
        ConcurrentLinkedSiblingPrefixTree other = new ConcurrentLinkedSiblingPrefixTree();
        tree.add("emp");
        assertFalse(other.contains("emp"));
        assertEquals(0, other.size());
    }

    /** Checks that pruning a leaf keeps its stored ancestor and neighboring branch. */
    @Test
    void removesLeafAndPreservesSiblingAndStoredPrefix() {
        tree.add("car");
        tree.add("cart");
        tree.add("cat");
        assertTrue(tree.remove("cart"));
        assertFalse(tree.startsWith("cart"));
        assertTrue(tree.contains("car"));
        assertTrue(tree.contains("cat"));
        assertTrue(tree.remove("car"));
        assertFalse(tree.startsWith("car"));
        assertTrue(tree.contains("cat"));
        assertEquals(1, tree.size());
    }

    /** Checks that removing terminal flags keeps paths needed by longer keys. */
    @Test
    void removesStoredPrefixAndEmptyKeyWithoutRemovingDescendants() {
        tree.add("");
        tree.add("car");
        tree.add("cart");
        assertTrue(tree.remove(""));
        assertFalse(tree.contains(""));
        assertTrue(tree.remove("car"));
        assertFalse(tree.contains("car"));
        assertTrue(tree.startsWith("car"));
        assertTrue(tree.contains("cart"));
        assertEquals(1, tree.size());
    }

    /** Checks failed removal, pruning of the last key, and reinsertion. */
    @Test
    void missingKeysLeaveTreeIntactAndRemovingLastKeyPrunesEntireBranch() {
        tree.add("cart");
        assertFalse(tree.remove("car"));
        assertFalse(tree.remove("cars"));
        assertThrows(NullPointerException.class, () -> tree.remove(null));
        assertEquals(1, tree.size());
        assertTrue(tree.remove("cart"));
        assertFalse(tree.remove("cart"));
        assertFalse(tree.startsWith("c"));
        assertFalse(tree.startsWith(""));
        assertEquals(0, tree.size());
        assertTrue(tree.add("cart"));
        assertTrue(tree.contains("cart"));
    }

    /** Checks replacement and pruning while an unrelated key remains. */
    @Test
    void replacesKeyAndPrunesUnusedBranch() {
        tree.add("car");
        tree.add("dog");
        assertTrue(tree.replace("car", "cat"));
        assertFalse(tree.startsWith("car"));
        assertTrue(tree.contains("cat"));
        assertTrue(tree.contains("dog"));
        assertEquals(2, tree.size());
    }

    /** Checks replacement across overlapping paths and the empty key. */
    @Test
    void replacesWithLongerAndShorterKeysIncludingEmptyKey() {
        tree.add("");
        tree.add("cart");
        assertTrue(tree.replace("", "car"));
        assertFalse(tree.contains(""));
        assertTrue(tree.replace("cart", "carter"));
        assertFalse(tree.contains("cart"));
        assertTrue(tree.startsWith("cart"));
        assertTrue(tree.replace("carter", ""));
        assertFalse(tree.startsWith("cart"));
        assertTrue(tree.contains("car"));
        assertTrue(tree.contains(""));
        assertEquals(2, tree.size());
    }

    /** Checks that missing, duplicate, equal, and null replacement inputs preserve the tree. */
    @Test
    void unsuccessfulReplacementLeavesKeysIntact() {
        tree.add("car");
        tree.add("cart");
        assertFalse(tree.replace("ca", "cat"));
        assertFalse(tree.replace("car", "cart"));
        assertFalse(tree.replace("car", new String("car")));
        assertThrows(NullPointerException.class, () -> tree.replace(null, "cat"));
        assertThrows(NullPointerException.class, () -> tree.replace("car", null));
        assertFalse(tree.startsWith("cat"));
        assertTrue(tree.contains("car"));
        assertTrue(tree.contains("cart"));
        assertEquals(2, tree.size());
    }

    /** Checks that unlinking middle, first, and last siblings preserves the others. */
    @Test
    void unlinksSiblingsAtEveryPosition() {
        tree.add("chetan");
        tree.add("chetak");
        tree.add("chetal");
        tree.add("chetam");

        // Remove from the middle first, then from the head and tail.
        assertTrue(tree.remove("chetak"));
        assertTrue(tree.contains("chetan"));
        assertTrue(tree.contains("chetal"));
        assertTrue(tree.remove("chetan"));
        assertTrue(tree.remove("chetam"));
        assertTrue(tree.contains("chetal"));
        assertFalse(tree.startsWith("chetam"));
        assertEquals(1, tree.size());
    }

    /** Competing updates to the same key must each have exactly one winner. */
    @Test
    void competingUpdatesHaveOneWinner() throws Exception {
        assertEquals(1, countSuccesses(race(() -> tree.add("shared"))));
        assertEquals(1, countSuccesses(race(() -> tree.replace("shared", "next"))));
        assertTrue(tree.contains("next"));
        assertEquals(1, tree.size());
        assertEquals(1, countSuccesses(race(() -> tree.remove("next"))));
        assertEquals(0, tree.size());
    }

    /** Readers must see one key while writers repeatedly replace it. */
    @Test
    void readersNeverSeeIntermediateReplacementCount() throws Exception {
        tree.add("left");
        race(() -> {
            for (int i = 0; i < 1_000; i++) {
                tree.replace("left", "right");
                tree.replace("right", "left");
                // Every published state has exactly one key.
                assertEquals(1, tree.size());
                assertTrue(tree.startsWith(""));
            }
            return true;
        });
    }

    private int countSuccesses(List<Boolean> results) {
        return (int) results.stream().filter(Boolean::booleanValue).count();
    }

    private List<Boolean> race(Callable<Boolean> action) throws Exception {
        int threads = 8;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                futures.add(executor.submit(() -> {
                    ready.countDown();
                    assertTrue(start.await(5, TimeUnit.SECONDS));
                    return action.call();
                }));
            }
            // Release all workers together and propagate failures on the test thread.
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            List<Boolean> results = new ArrayList<>();
            for (Future<Boolean> future : futures) {
                results.add(future.get(5, TimeUnit.SECONDS));
            }
            return results;
        } finally {
            start.countDown();
            executor.shutdownNow();
        }
    }
}
