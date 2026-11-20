package com.chetankhandave.utility.certificate;

import java.io.IOException;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;

/** Builds a PKIX path from supplied unordered certificates to explicitly approved trust entries. */
public final class TruststoreValidator implements ValidationCheck {
    public enum Revocation { DISABLED, REQUIRED }
    private final X509Certificate leaf;
    private final List<X509Certificate> candidates;
    private final Map<String,X509Certificate> anchors;
    private final Instant at;
    private final Revocation revocation;
    public TruststoreValidator(X509Certificate leaf,Collection<X509Certificate> candidates,
            Map<String,X509Certificate> anchors,Instant at,Revocation revocation) {
        this.leaf=leaf;this.candidates=Collections.unmodifiableList(new ArrayList<>(candidates));
        Map<String,X509Certificate> copy=new TreeMap<>(anchors);
        for(Map.Entry<String,X509Certificate> anchor:copy.entrySet()) {
            if(anchor.getKey()==null || anchor.getKey().trim().isEmpty()) throw new IllegalArgumentException("Blank anchor alias");
            Objects.requireNonNull(anchor.getValue(),"anchor certificate");
        }
        for(X509Certificate candidate:this.candidates) Objects.requireNonNull(candidate,"candidate certificate");
        this.anchors=Collections.unmodifiableMap(copy);this.at=Objects.requireNonNull(at,"at");this.revocation=Objects.requireNonNull(revocation,"revocation");
    }
    /** Only selected TrustedCertificateEntry aliases become anchors; private-key entries are rejected. */
    public static Map<String,X509Certificate> readAnchors(Path file,String type,char[] password,Set<String> aliases)
            throws IOException,GeneralSecurityException {
        if(aliases.isEmpty()) throw new IllegalArgumentException("Explicit trust anchor aliases are required");
        return readAnchors(KeyStoreLoader.load(file,type,password),aliases);
    }
    /** Package-level adapter for a single loaded snapshot of the truststore. */
    static Map<String,X509Certificate> readAnchors(KeyStore store,Set<String> aliases) throws KeyStoreException {
        if(aliases.isEmpty()) throw new IllegalArgumentException("Explicit trust anchor aliases are required");
        Map<String,X509Certificate> result=new TreeMap<>();
        for(String alias:aliases) {
            if(!store.isCertificateEntry(alias) || !(store.getCertificate(alias) instanceof X509Certificate))
                throw new KeyStoreException("Selected alias must be an X.509 trusted certificate entry: "+alias);
            result.put(alias,(X509Certificate)store.getCertificate(alias));
        }
        return Collections.unmodifiableMap(result);
    }
    @Override public String getName() { return "truststore"; }
    @Override public ValidationResult validate() throws GeneralSecurityException {
        List<ValidationFinding> f=new ArrayList<>();
        f.add(new ValidationFinding("trust.revocation",ValidationStatus.NOT_CHECKED,
            revocation==Revocation.REQUIRED?"Revocation was required but no revocation mechanism is configured":"Revocation explicitly disabled by policy; no revocation assurance",revocation==Revocation.REQUIRED));
        if(leaf==null) {
            f.add(ValidationFinding.test("trust.present",false,"New leaf certificate is missing"));return new ValidationResult(getName(),f);
        }
        if(anchors.isEmpty()) {
            f.add(ValidationFinding.test("trust.anchors",false,"No approved trust anchors supplied"));return new ValidationResult(getName(),f);
        }
        try { leaf.checkValidity(Date.from(at)); }
        catch(CertificateException e) { f.add(ValidationFinding.test("trust.leaf-validity",false,"Leaf certificate is outside its validity period"));return new ValidationResult(getName(),f); }
        Set<TrustAnchor> trust=new HashSet<>();
        // Explicit anchors are additionally required to be valid CAs under this utility's local policy.
        for(Map.Entry<String,X509Certificate> anchor:anchors.entrySet()) {
            boolean valid=anchor.getValue().getBasicConstraints()>=0;
            boolean[] usage=anchor.getValue().getKeyUsage();valid&=usage==null || usage.length>5 && usage[5];
            try { anchor.getValue().checkValidity(Date.from(at)); } catch(CertificateException e) { valid=false; }
            f.add(ValidationFinding.test("trust.anchor."+anchor.getKey(),valid,"Selected anchor must be a currently valid CA with permitted certificate signing: "+anchor.getKey()));
            if(valid) trust.add(new TrustAnchor(anchor.getValue(),null));
        }
        if(trust.isEmpty()) return new ValidationResult(getName(),f);
        X509CertSelector selector=new X509CertSelector();selector.setCertificate(leaf);
        PKIXBuilderParameters parameters=new PKIXBuilderParameters(trust,selector);
        parameters.setDate(Date.from(at)); parameters.setRevocationEnabled(false);parameters.setMaxPathLength(-1);
        List<X509Certificate> pool=new ArrayList<>(candidates);pool.add(leaf);
        parameters.addCertStore(CertStore.getInstance("Collection",new CollectionCertStoreParameters(pool)));
        try {
            PKIXCertPathBuilderResult built=(PKIXCertPathBuilderResult)CertPathBuilder.getInstance("PKIX").build(parameters);
            String selected="UNKNOWN";
            for(Map.Entry<String,X509Certificate> anchor:anchors.entrySet()) if(anchor.getValue().equals(built.getTrustAnchor().getTrustedCert())) { selected=anchor.getKey();break; }
            f.add(ValidationFinding.test("trust.path",true,"PKIX path built with "+built.getCertPath().getCertificates().size()+" certificate(s); anchor alias: "+selected));
        } catch(CertPathBuilderException e) {
            f.add(ValidationFinding.test("trust.path",false,"No valid PKIX path to an approved anchor (check issuers, signatures, validity and constraints)"));
        }
        return new ValidationResult(getName(),f);
    }
}
