package com.chetankhandave.utility.certificate;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.*;
import java.time.*;
import java.util.*;

/** Reads X.509 PEM/DER/bundles and produces deterministic public metadata reports. */
public final class CertificateAnalyzer {
    private final Clock clock;
    private final List<CertificateRule> rules;
    public CertificateAnalyzer() { this(Clock.systemUTC(), Collections.emptyList()); }
    public CertificateAnalyzer(Clock clock, List<CertificateRule> rules) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.rules = Collections.unmodifiableList(new ArrayList<>(rules));
    }
    /** Caller owns the input stream; certificate order follows the input encoding. */
    public List<X509Certificate> read(InputStream input) throws CertificateException {
        List<X509Certificate> result = new ArrayList<>();
        for (java.security.cert.Certificate c : CertificateFactory.getInstance("X.509")
                .generateCertificates(Objects.requireNonNull(input, "input"))) {
            result.add((X509Certificate)c);
        }
        if (result.isEmpty()) throw new CertificateException("No X.509 certificates found");
        return Collections.unmodifiableList(result);
    }
    public List<X509Certificate> read(Path path) throws IOException, CertificateException {
        try (InputStream input = Files.newInputStream(path)) { return read(input); }
    }
    public AnalysisReport analyze(X509Certificate c) throws GeneralSecurityException {
        Objects.requireNonNull(c, "certificate");
        Instant now = clock.instant();
        Map<String,String> d = new LinkedHashMap<>();
        List<String> f = new ArrayList<>();
        d.put("subject", c.getSubjectX500Principal().getName());
        d.put("issuer", c.getIssuerX500Principal().getName());
        d.put("serialHex", c.getSerialNumber().toString(16));
        d.put("version", String.valueOf(c.getVersion()));
        d.put("notBefore", c.getNotBefore().toInstant().toString());
        d.put("notAfter", c.getNotAfter().toInstant().toString());
        d.put("analyzedAt", now.toString());
        d.put("remainingWholeDays", String.valueOf(Duration.between(now,c.getNotAfter().toInstant()).toDays()));
        try { c.checkValidity(Date.from(now)); d.put("validity", "VALID"); }
        catch (CertificateExpiredException e) { d.put("validity", "EXPIRED"); f.add("Certificate has expired"); }
        catch (CertificateNotYetValidException e) { d.put("validity", "NOT_YET_VALID"); f.add("Certificate is not yet valid"); }
        d.put("signatureAlgorithm", c.getSigAlgName());
        d.put("signatureOid", c.getSigAlgOID());
        PublicKey key = c.getPublicKey();
        d.put("publicKeyAlgorithm", key.getAlgorithm());
        int bits = key instanceof RSAKey ? ((RSAKey)key).getModulus().bitLength()
            : key instanceof ECKey ? ((ECKey)key).getParams().getCurve().getField().getFieldSize()
            : key instanceof DSAKey ? ((DSAKey)key).getParams().getP().bitLength() : -1;
        d.put("publicKeyBits", bits < 0 ? "UNKNOWN" : String.valueOf(bits));
        d.put("sha256Fingerprint", hex(MessageDigest.getInstance("SHA-256").digest(c.getEncoded())));
        d.put("publicKeySha256", hex(MessageDigest.getInstance("SHA-256").digest(key.getEncoded())));
        d.put("basicConstraints", String.valueOf(c.getBasicConstraints()));
        d.put("keyUsage", Arrays.toString(c.getKeyUsage()));
        d.put("extendedKeyUsage", String.valueOf(c.getExtendedKeyUsage()));
        d.put("subjectAlternativeNames", String.valueOf(c.getSubjectAlternativeNames()));
        d.put("issuerAlternativeNames", String.valueOf(c.getIssuerAlternativeNames()));
        d.put("criticalExtensionOids", String.valueOf(c.getCriticalExtensionOIDs()));
        d.put("nonCriticalExtensionOids", String.valueOf(c.getNonCriticalExtensionOIDs()));
        Set<String> oids = new TreeSet<>();
        if(c.getCriticalExtensionOIDs()!=null) oids.addAll(c.getCriticalExtensionOIDs());
        if(c.getNonCriticalExtensionOIDs()!=null) oids.addAll(c.getNonCriticalExtensionOIDs());
        // Preserve unknown extensions as DER rather than silently discarding them.
        for(String oid:oids) d.put("extensionDerBase64."+oid, Base64.getEncoder().encodeToString(c.getExtensionValue(oid)));
        boolean selfSigned = false;
        if(c.getSubjectX500Principal().equals(c.getIssuerX500Principal())) {
            try { c.verify(key); selfSigned = true; } catch(GeneralSecurityException e) { f.add("Self-issued certificate does not verify with its own key"); }
        }
        d.put("selfSigned", String.valueOf(selfSigned));
        if(c.hasUnsupportedCriticalExtension()) f.add("Unsupported critical extension");
        if(key instanceof RSAKey && bits < 2048) f.add("RSA key below local 2048-bit policy");
        String sig=c.getSigAlgName().toUpperCase(Locale.ROOT).replace("-", "");
        if(sig.contains("SHA1")||sig.contains("MD5")||sig.contains("MD2")) f.add("Legacy signature digest");
        if(!now.isAfter(c.getNotAfter().toInstant()) && c.getNotAfter().toInstant().isBefore(now.plus(Duration.ofDays(30)))) f.add("Expires within 30 days");
        for(CertificateRule rule:rules) rule.evaluate(c,now,f);
        return new AnalysisReport(d,f);
    }
    private static String hex(byte[] bytes) {
        StringBuilder out=new StringBuilder();
        for(byte b:bytes) out.append(String.format(Locale.ROOT,"%02X", b & 255));
        return out.toString();
    }
}
