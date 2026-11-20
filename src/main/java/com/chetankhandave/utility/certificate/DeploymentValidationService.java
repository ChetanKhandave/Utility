package com.chetankhandave.utility.certificate;

import java.io.IOException;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.*;
import java.util.*;

/** Facade orchestrates comparison and independent strategies at one captured validation instant. */
public final class DeploymentValidationService {
    private final Clock clock;
    public DeploymentValidationService() { this(Clock.systemUTC()); }
    public DeploymentValidationService(Clock clock) { this.clock=Objects.requireNonNull(clock,"clock"); }
    public DeploymentValidationReport validate(Path before,String beforeType,char[] beforePassword,
            Path after,String afterType,char[] afterPassword,Path truststore,String trustType,char[] trustPassword,
            DeploymentValidationPolicy policy) throws IOException,GeneralSecurityException {
        Objects.requireNonNull(policy,"policy");Instant at=clock.instant();
        KeyStore oldStore=KeyStoreLoader.load(before,beforeType,beforePassword),newStore=KeyStoreLoader.load(after,afterType,afterPassword);
        KeyStoreComparison comparison=new KeyStoreComparator(Clock.fixed(at,ZoneOffset.UTC)).compare(oldStore,newStore);
        X509Certificate oldLeaf=certificate(oldStore,policy.alias),newLeaf=certificate(newStore,policy.alias);
        List<ValidationCheck> checks=Arrays.asList(new ExpectedChangeValidator(comparison,policy.expected),
            new RenewalValidator(oldLeaf,newLeaf,policy.renewal,at),new ValidationCheck() {
                @Override public String getName() { return "truststore"; }
                @Override public ValidationResult validate() throws Exception {
                    // Defer truststore I/O so its failure cannot hide renewal/expected-change findings.
                    KeyStore trusted=KeyStoreLoader.load(truststore,trustType,trustPassword);
                    Map<String,X509Certificate> anchors=TruststoreValidator.readAnchors(trusted,policy.anchors);
                    List<X509Certificate> candidates=certificates(newStore);
                    candidates.addAll(certificates(trusted));
                    return new TruststoreValidator(newLeaf,candidates,anchors,at,policy.revocation).validate();
                }
            });
        return new DeploymentValidationReport(comparison,new ValidationCoordinator().run(checks));
    }
    private static X509Certificate certificate(KeyStore store,String alias) throws KeyStoreException {
        java.security.cert.Certificate c=store.getCertificate(alias);return c instanceof X509Certificate?(X509Certificate)c:null;
    }
    private static List<X509Certificate> certificates(KeyStore store) throws KeyStoreException {
        List<X509Certificate> result=new ArrayList<>();
        for(String alias:Collections.list(store.aliases())) {
            java.security.cert.Certificate[] chain=store.getCertificateChain(alias);
            if(chain!=null) for(java.security.cert.Certificate c:chain) { if(c instanceof X509Certificate) result.add((X509Certificate)c); }
            else { X509Certificate c=certificate(store,alias);if(c!=null) result.add(c); }
        }
        return result;
    }
}
