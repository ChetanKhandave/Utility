package com.chetankhandave.utility.certificate;

import java.time.Duration;
import java.net.IDN;
import java.util.*;

/** Builder configures renewal requirements independently of renewal execution. */
public final class RenewalPolicy {
    public enum PublicKeyRule { ANY, MUST_CHANGE, MUST_REMAIN }
    final Duration minimumRemaining;
    final Set<String> dnsNames,ekuOids;
    final Set<Integer> keyUsage;
    final boolean laterExpiry,preserveSubject,endEntity;
    final PublicKeyRule publicKeyRule;
    private RenewalPolicy(Builder b) {
        minimumRemaining=b.minimumRemaining; dnsNames=Collections.unmodifiableSet(new TreeSet<>(b.dnsNames));
        ekuOids=Collections.unmodifiableSet(new TreeSet<>(b.ekuOids)); keyUsage=Collections.unmodifiableSet(new TreeSet<>(b.keyUsage));
        laterExpiry=b.laterExpiry;preserveSubject=b.preserveSubject;endEntity=b.endEntity;publicKeyRule=b.publicKeyRule;
    }
    public static Builder builder() { return new Builder(); }
    static String dns(String value) {
        Objects.requireNonNull(value,"DNS name");
        String trimmed=value.endsWith(".")?value.substring(0,value.length()-1):value;
        if(trimmed.isEmpty() || trimmed.contains("*") || !trimmed.equals(trimmed.trim())) throw new IllegalArgumentException("Require an explicit DNS SAN name, without wildcard");
        return IDN.toASCII(trimmed,IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
    }
    public static final class Builder {
        private Duration minimumRemaining=Duration.ofDays(90);
        private final Set<String> dnsNames=new TreeSet<>(),ekuOids=new TreeSet<>();
        private final Set<Integer> keyUsage=new TreeSet<>();
        private boolean laterExpiry=true,preserveSubject=true,endEntity=true;
        private PublicKeyRule publicKeyRule=PublicKeyRule.ANY;
        public Builder minimumRemaining(Duration duration) {
            if(Objects.requireNonNull(duration,"duration").isNegative()) throw new IllegalArgumentException("Negative remaining validity");
            minimumRemaining=duration;return this;
        }
        /** Required DNS SAN values use exact IDN/case-normalized matching; no CN or wildcard fallback. */
        public Builder requireDnsName(String name) { dnsNames.add(dns(name));return this; }
        public Builder requireEku(String oid) {
            if(oid==null || !oid.matches("[0-2](\\.[0-9]+)+")) throw new IllegalArgumentException("Invalid EKU OID");
            ekuOids.add(oid);return this;
        }
        public Builder requireKeyUsage(int bit) {
            if(bit<0 || bit>8) throw new IllegalArgumentException("Key usage bit must be 0..8");keyUsage.add(bit);return this;
        }
        public Builder requireLaterExpiry(boolean value) { laterExpiry=value;return this; }
        public Builder preserveSubject(boolean value) { preserveSubject=value;return this; }
        public Builder requireEndEntity(boolean value) { endEntity=value;return this; }
        public Builder publicKeyRule(PublicKeyRule rule) { publicKeyRule=Objects.requireNonNull(rule,"rule");return this; }
        public RenewalPolicy build() { return new RenewalPolicy(this); }
    }
}
