package com.chetankhandave.utility.certificate;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;

/** Read-only JKS/PKCS12 analysis. Each call loads its own store; passwords are never retained. */
public final class KeyStoreAnalyzer {
    @FunctionalInterface
    public interface KeyPasswordProvider {
        /** Return a fresh array owned by the analyzer, or null to skip recovery. */
        char[] passwordFor(String alias);
    }
    private final CertificateAnalyzer certificates;
    private final KeyPairVerifier verifier;
    public KeyStoreAnalyzer() { this(new CertificateAnalyzer(),new KeyPairVerifier()); }
    public KeyStoreAnalyzer(CertificateAnalyzer certificates, KeyPairVerifier verifier) {
        this.certificates=Objects.requireNonNull(certificates,"certificates");
        this.verifier=Objects.requireNonNull(verifier,"verifier");
    }
    /** Requires an integrity password; null is rejected to avoid unchecked store loading. */
    public Map<String,List<AnalysisReport>> analyze(Path file, String type, char[] storePassword,
            KeyPasswordProvider passwords) throws IOException, GeneralSecurityException {
        Objects.requireNonNull(storePassword,"storePassword (integrity verification required)");
        if(!"JKS".equalsIgnoreCase(type) && !"PKCS12".equalsIgnoreCase(type)) throw new IllegalArgumentException("Use JKS or PKCS12");
        KeyStore store=KeyStore.getInstance(type);
        char[] copy=storePassword.clone();
        try(InputStream input=Files.newInputStream(file)) { store.load(input,copy); }
        finally { Arrays.fill(copy,'\0'); }
        List<String> aliases=Collections.list(store.aliases()); Collections.sort(aliases);
        Map<String,List<AnalysisReport>> result=new LinkedHashMap<>();
        for(String alias:aliases) {
            Map<String,String> d=new LinkedHashMap<>(); List<String> findings=new ArrayList<>();
            d.put("alias",alias); d.put("storeType",store.getType()); d.put("provider",store.getProvider().getName());
            Date created=store.getCreationDate(alias); d.put("created",created==null?"UNKNOWN":created.toInstant().toString());
            String kind=store.entryInstanceOf(alias,KeyStore.PrivateKeyEntry.class)?"PRIVATE_KEY"
                :store.entryInstanceOf(alias,KeyStore.SecretKeyEntry.class)?"SECRET_KEY":"TRUSTED_CERTIFICATE";
            d.put("entryType",kind); d.put("keyPairMatch","NOT_CHECKED");
            java.security.cert.Certificate leaf=store.getCertificate(alias);
            if("PRIVATE_KEY".equals(kind) && passwords!=null) {
                char[] password=passwords.passwordFor(alias);
                if(password!=null) {
                    try {
                        Key key=store.getKey(alias,password);
                        if(key instanceof PrivateKey && leaf!=null) d.put("keyPairMatch",verifier.verify((PrivateKey)key,leaf.getPublicKey()).name());
                    } catch(UnrecoverableKeyException e) { findings.add("Key recovery failed; entry password may be incorrect"); }
                    finally { Arrays.fill(password,'\0'); }
                }
            }
            List<AnalysisReport> reports=new ArrayList<>(); reports.add(new AnalysisReport(d,findings));
            java.security.cert.Certificate[] chain=store.getCertificateChain(alias);
            if(chain==null && leaf!=null) chain=new java.security.cert.Certificate[]{leaf};
            if(chain!=null) {
                List<X509Certificate> x509=new ArrayList<>();
                for(java.security.cert.Certificate c:chain) if(c instanceof X509Certificate) {
                    x509.add((X509Certificate)c); reports.add(certificates.analyze((X509Certificate)c));
                }
                if(!x509.isEmpty()) reports.add(new ChainAnalyzer().inspect(x509,java.time.Instant.parse(reports.get(1).getDetails().get("analyzedAt"))));
            }
            result.put(alias,Collections.unmodifiableList(reports));
        }
        return Collections.unmodifiableMap(result);
    }
}
