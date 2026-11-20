package com.chetankhandave.utility.certificate;

import java.util.*;

/** Immutable exact-alias allowlist plus optional mandatory observed changes and required aliases. */
public final class ExpectedChangePolicy {
    final Map<String,Set<KeyStoreComparison.Status>> allowed,required;
    final Set<String> requiredAliases;
    public ExpectedChangePolicy(Map<String,Set<KeyStoreComparison.Status>> allowed,
            Map<String,Set<KeyStoreComparison.Status>> required,Set<String> requiredAliases) {
        this.allowed=copy(allowed); this.required=copy(required);
        this.requiredAliases=Collections.unmodifiableSet(new TreeSet<>(requiredAliases));
        for(String alias:this.requiredAliases) requireAlias(alias);
        for(Map.Entry<String,Set<KeyStoreComparison.Status>> entry:this.required.entrySet())
            if(!this.allowed.containsKey(entry.getKey()) || !this.allowed.get(entry.getKey()).containsAll(entry.getValue()))
                throw new IllegalArgumentException("Required changes must also be allowed");
    }
    private static Map<String,Set<KeyStoreComparison.Status>> copy(Map<String,Set<KeyStoreComparison.Status>> input) {
        Map<String,Set<KeyStoreComparison.Status>> result=new TreeMap<>();
        for(Map.Entry<String,Set<KeyStoreComparison.Status>> entry:input.entrySet()) {
            requireAlias(entry.getKey()); Set<KeyStoreComparison.Status> statuses=EnumSet.noneOf(KeyStoreComparison.Status.class);
            statuses.addAll(entry.getValue());
            if(statuses.isEmpty() || statuses.contains(KeyStoreComparison.Status.UNCHANGED) || statuses.contains(KeyStoreComparison.Status.NOT_COMPARABLE))
                throw new IllegalArgumentException("Only ADDED, REMOVED, CHANGED and METADATA_CHANGED can be approved");
            result.put(entry.getKey(),Collections.unmodifiableSet(statuses));
        }
        return Collections.unmodifiableMap(result);
    }
    private static void requireAlias(String alias) {
        if(alias==null || alias.trim().isEmpty()) throw new IllegalArgumentException("Alias must not be blank");
    }
}
