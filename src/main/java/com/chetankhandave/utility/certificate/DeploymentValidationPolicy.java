package com.chetankhandave.utility.certificate;

import java.time.Duration;
import java.util.*;

/** Strict .properties adapter: unknown keys and malformed values fail before secret prompts. */
public final class DeploymentValidationPolicy {
    final String alias;
    final ExpectedChangePolicy expected;
    final RenewalPolicy renewal;
    final Set<String> anchors;
    final TruststoreValidator.Revocation revocation;
    private DeploymentValidationPolicy(String alias,ExpectedChangePolicy expected,RenewalPolicy renewal,
            Set<String> anchors,TruststoreValidator.Revocation revocation) {
        this.alias=alias;this.expected=expected;this.renewal=renewal;
        this.anchors=Collections.unmodifiableSet(new TreeSet<>(anchors));this.revocation=revocation;
    }
    public static DeploymentValidationPolicy fromProperties(Properties p) {
        Objects.requireNonNull(p,"properties");
        Set<String> known=new HashSet<>(Arrays.asList("target.alias","requiredAliases","renewal.requiredDnsNames",
            "renewal.minimumRemainingDays","renewal.requireLaterExpiry","renewal.preserveSubject","renewal.requireEndEntity",
            "renewal.publicKey","renewal.requiredKeyUsage","renewal.requiredEku","trust.anchorAliases","trust.revocation"));
        Map<String,Set<KeyStoreComparison.Status>> allowed=new TreeMap<>(),required=new TreeMap<>();
        for(String key:p.stringPropertyNames()) {
            if(key.startsWith("allowChange.")) allowed.put(key.substring(12),statuses(p.getProperty(key)));
            else if(key.startsWith("requireChange.")) required.put(key.substring(14),statuses(p.getProperty(key)));
            else if(!known.contains(key)) throw new IllegalArgumentException("Unknown policy property: "+key);
        }
        String alias=p.getProperty("target.alias","").trim();if(alias.isEmpty()) throw new IllegalArgumentException("target.alias is required");
        Set<String> anchors=csv(p.getProperty("trust.anchorAliases",""));if(anchors.isEmpty()) throw new IllegalArgumentException("trust.anchorAliases is required");
        RenewalPolicy.Builder renewal=RenewalPolicy.builder()
            .minimumRemaining(Duration.ofDays(Long.parseLong(p.getProperty("renewal.minimumRemainingDays","90").trim())))
            .requireLaterExpiry(bool(p,"renewal.requireLaterExpiry",true)).preserveSubject(bool(p,"renewal.preserveSubject",true))
            .requireEndEntity(bool(p,"renewal.requireEndEntity",true))
            .publicKeyRule(RenewalPolicy.PublicKeyRule.valueOf(p.getProperty("renewal.publicKey","ANY").trim().toUpperCase(Locale.ROOT)));
        for(String dns:csv(p.getProperty("renewal.requiredDnsNames",""))) renewal.requireDnsName(dns);
        for(String oid:csv(p.getProperty("renewal.requiredEku",""))) renewal.requireEku(oid);
        for(String bit:csv(p.getProperty("renewal.requiredKeyUsage",""))) renewal.requireKeyUsage(Integer.parseInt(bit));
        return new DeploymentValidationPolicy(alias,new ExpectedChangePolicy(allowed,required,csv(p.getProperty("requiredAliases",""))),renewal.build(),anchors,
            TruststoreValidator.Revocation.valueOf(p.getProperty("trust.revocation","DISABLED").trim().toUpperCase(Locale.ROOT)));
    }
    private static boolean bool(Properties p,String key,boolean fallback) {
        String value=p.getProperty(key,String.valueOf(fallback)).trim();
        if(!"true".equalsIgnoreCase(value) && !"false".equalsIgnoreCase(value)) throw new IllegalArgumentException("Expected true/false for "+key);
        return Boolean.parseBoolean(value);
    }
    private static Set<String> csv(String value) {
        Set<String> result=new TreeSet<>();
        if(value.trim().isEmpty()) return result;
        for(String item:value.split(",",-1)) {
            if(item.trim().isEmpty()) throw new IllegalArgumentException("Empty item in policy list");result.add(item.trim());
        }
        return result;
    }
    private static Set<KeyStoreComparison.Status> statuses(String value) {
        Set<KeyStoreComparison.Status> result=EnumSet.noneOf(KeyStoreComparison.Status.class);
        for(String item:csv(value)) result.add(KeyStoreComparison.Status.valueOf(item.toUpperCase(Locale.ROOT)));return result;
    }
}
