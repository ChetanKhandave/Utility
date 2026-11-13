package com.chetankhandave.utility.trie;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PrefixTreeTest {

    private final PrefixTree tree = new PrefixTree();

    @Test
    void emptyTreeHasNoKeysOrPrefixes() {
        assertEquals(0, tree.size());
        assertFalse(tree.contains(""));
        assertFalse(tree.contains("emp"));
        assertFalse(tree.startsWith(""));
        assertFalse(tree.startsWith("emp"));
    }

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

    @Test
    void longerKeyPreservesExistingShorterKeyAndDuplicateDoesNotChangeSize() {
        assertTrue(tree.add("emp"));
        assertTrue(tree.add("employee"));
        assertFalse(tree.add(new String("emp")));
        assertTrue(tree.contains("emp"));
        assertEquals(2, tree.size());
    }

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

    @Test
    void nullIsRejectedWithoutChangingTree() {
        assertThrows(NullPointerException.class, () -> tree.add(null));
        assertThrows(NullPointerException.class, () -> tree.contains(null));
        assertThrows(NullPointerException.class, () -> tree.startsWith(null));
        assertEquals(0, tree.size());
    }

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

    @Test
    void instancesMaintainIndependentState() {
        PrefixTree other = new PrefixTree();
        tree.add("emp");
        assertFalse(other.contains("emp"));
        assertEquals(0, other.size());
    }

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
}
