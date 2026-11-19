package com.chetankhandave.utility.certificate;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.time.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Integration fixtures use the installed JDK's keytool, without internal JDK APIs. */
class CertificateUtilityTest {
    @TempDir static Path directory;
    static Path jks, p12;
    static X509Certificate certificate;
    static PrivateKey privateKey;
    static Instant at;
    @BeforeAll static void fixtures() throws Exception {
        jks=directory.resolve("test.jks"); p12=directory.resolve("test.p12");
        for(String type:Arrays.asList("JKS","PKCS12")) {
            Path target="JKS".equals(type)?jks:p12;
            String executable=Paths.get(System.getProperty("java.home"),"bin",System.getProperty("os.name").startsWith("Windows")?"keytool.exe":"keytool").toString();
            Process process=new ProcessBuilder(executable,"-genkeypair","-alias","server","-keyalg","RSA","-keysize","2048",
                "-dname","CN=localhost","-ext","SAN=dns:localhost,ip:127.0.0.1","-validity","365",
                "-storetype",type,"-keystore",target.toString(),"-storepass","test-only-password","-keypass","test-only-password","-noprompt")
                .redirectErrorStream(true).redirectOutput(directory.resolve(type+".log").toFile()).start();
            assertEquals(0,process.waitFor(),"keytool fixture generation failed");
        }
        KeyStore store=KeyStore.getInstance("JKS");
        try(InputStream in=Files.newInputStream(jks)) { store.load(in,password()); }
        certificate=(X509Certificate)store.getCertificate("server");
        privateKey=(PrivateKey)store.getKey("server",password());
        at=certificate.getNotBefore().toInstant().plusSeconds(60);
    }
    static char[] password() { return "test-only-password".toCharArray(); }
    CertificateAnalyzer analyzer(Instant time) { return new CertificateAnalyzer(Clock.fixed(time,ZoneOffset.UTC),Collections.emptyList()); }
    @Test void reportsMetadataAndExtensions() throws Exception {
        Map<String,String> d=analyzer(at).analyze(certificate).getDetails();
        assertEquals("VALID",d.get("validity")); assertEquals("2048",d.get("publicKeyBits"));
        assertEquals("true",d.get("selfSigned")); assertEquals(64,d.get("sha256Fingerprint").length());
        assertTrue(d.get("subjectAlternativeNames").contains("localhost"));
        assertTrue(d.containsKey("extensionDerBase64.2.5.29.17"));
    }
    @Test void detectsExpired() throws Exception { assertEquals("EXPIRED",analyzer(certificate.getNotAfter().toInstant().plusSeconds(1)).analyze(certificate).getDetails().get("validity")); }
    @Test void detectsNotYetValid() throws Exception { assertEquals("NOT_YET_VALID",analyzer(certificate.getNotBefore().toInstant().minusSeconds(1)).analyze(certificate).getDetails().get("validity")); }
    @Test void detectsExpiryWindow() throws Exception { assertTrue(analyzer(certificate.getNotAfter().toInstant().minusSeconds(3600)).analyze(certificate).getFindings().contains("Expires within 30 days")); }
    @Test void customPolicyIsInvoked() throws Exception {
        CertificateRule rule=(c,t,f)->f.add("Custom policy finding");
        assertTrue(new CertificateAnalyzer(Clock.fixed(at,ZoneOffset.UTC),Arrays.asList(rule)).analyze(certificate).getFindings().contains("Custom policy finding"));
    }
    @Test void reportsAreImmutableAndDefensivelyCopied() {
        Map<String,String> values=new HashMap<>(); values.put("a","b"); List<String> findings=new ArrayList<>();
        AnalysisReport report=new AnalysisReport(values,findings); values.clear(); findings.add("changed");
        assertEquals("b",report.getDetails().get("a")); assertTrue(report.getFindings().isEmpty());
        assertThrows(UnsupportedOperationException.class,()->report.getDetails().clear());
        assertThrows(UnsupportedOperationException.class,()->report.getFindings().add("x"));
    }
    @Test void readsDerAndPemBundle() throws Exception {
        CertificateAnalyzer a=analyzer(at);
        assertEquals(1,a.read(new ByteArrayInputStream(certificate.getEncoded())).size());
        String pem="-----BEGIN CERTIFICATE-----\n"+Base64.getMimeEncoder().encodeToString(certificate.getEncoded())+"\n-----END CERTIFICATE-----\n";
        assertEquals(2,a.read(new ByteArrayInputStream((pem+pem).getBytes(java.nio.charset.StandardCharsets.US_ASCII))).size());
    }
    @Test void rejectsMalformedCertificate() { assertThrows(CertificateException.class,()->analyzer(at).read(new ByteArrayInputStream(new byte[]{1,2,3}))); }
    @Test void checksMatchingAndDifferentKeys() throws Exception {
        KeyPairVerifier verifier=new KeyPairVerifier();
        assertEquals(KeyPairVerifier.Result.MATCH,verifier.verify(privateKey,certificate.getPublicKey()));
        KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        assertEquals(KeyPairVerifier.Result.MISMATCH,verifier.verify(privateKey,generator.generateKeyPair().getPublic()));
    }
    @Test void supportsEcAndDsa() throws Exception {
        for(String algorithm:Arrays.asList("EC","DSA")) {
            KeyPairGenerator generator=KeyPairGenerator.getInstance(algorithm); generator.initialize("EC".equals(algorithm)?256:2048);
            KeyPair pair=generator.generateKeyPair();
            assertEquals(KeyPairVerifier.Result.MATCH,new KeyPairVerifier().verify(pair.getPrivate(),pair.getPublic()));
        }
    }
    @Test void loadsBothStoresAndClearsOwnedPassword() throws Exception {
        for(String type:Arrays.asList("JKS","PKCS12")) {
            char[] entry=password(), caller=password();
            Map<String,List<AnalysisReport>> result=new KeyStoreAnalyzer(analyzer(at),new KeyPairVerifier()).analyze("JKS".equals(type)?jks:p12,type,caller,alias->entry);
            assertEquals("PRIVATE_KEY",result.get("server").get(0).getDetails().get("entryType"));
            assertEquals("MATCH",result.get("server").get(0).getDetails().get("keyPairMatch"));
            assertArrayEquals(new char[entry.length],entry); assertArrayEquals(password(),caller);
            assertThrows(UnsupportedOperationException.class,()->result.clear());
        }
    }
    @Test void wrongStorePasswordFails() { assertThrows(IOException.class,()->new KeyStoreAnalyzer().analyze(jks,"JKS","wrong".toCharArray(),null)); }
    @Test void wrongEntryPasswordIsReported() throws Exception {
        assertFalse(new KeyStoreAnalyzer().analyze(jks,"JKS",password(),alias->"wrong".toCharArray()).get("server").get(0).getFindings().isEmpty());
    }
    @Test void nullPasswordRejected() { assertThrows(NullPointerException.class,()->new KeyStoreAnalyzer().analyze(jks,"JKS",null,null)); }
    @Test void supportsTrustedCertificateAndSecretKeyEntries() throws Exception {
        KeyStore store=KeyStore.getInstance("PKCS12");store.load(null,password());
        store.setCertificateEntry("trusted",certificate);
        store.setEntry("secret",new KeyStore.SecretKeyEntry(new javax.crypto.spec.SecretKeySpec(new byte[16],"AES")),new KeyStore.PasswordProtection(password()));
        Path path=directory.resolve("mixed.p12");try(OutputStream out=Files.newOutputStream(path)) { store.store(out,password()); }
        Map<String,List<AnalysisReport>> report=new KeyStoreAnalyzer().analyze(path,"PKCS12",password(),null);
        assertEquals("SECRET_KEY",report.get("secret").get(0).getDetails().get("entryType"));
        assertEquals("TRUSTED_CERTIFICATE",report.get("trusted").get(0).getDetails().get("entryType"));
    }
    @Test void signatureInspectionDoesNotClaimTrust() {
        AnalysisReport report=new ChainAnalyzer().inspect(Arrays.asList(certificate),at);
        assertEquals("NOT_EVALUATED",report.getDetails().get("trust")); assertEquals("NOT_CHECKED",report.getDetails().get("revocation"));
    }
    @Test void explicitTrustAnchorSucceeds() throws Exception {
        assertNotNull(new ChainAnalyzer().validate(Arrays.asList(certificate),Collections.singleton(new TrustAnchor(certificate,null)),at));
    }
    @Test void rejectsUntrustedPath() throws Exception {
        KeyStore store=KeyStore.getInstance("PKCS12");try(InputStream in=Files.newInputStream(p12)) { store.load(in,password()); }
        X509Certificate other=(X509Certificate)store.getCertificate("server");
        assertThrows(CertPathValidatorException.class,()->new ChainAnalyzer().validate(Arrays.asList(certificate),Collections.singleton(new TrustAnchor(other,null)),at));
        assertFalse(new ChainAnalyzer().inspect(Arrays.asList(certificate,other),at).getFindings().isEmpty());
    }
    @Test void rejectsEmptyChain() { assertThrows(IllegalArgumentException.class,()->new ChainAnalyzer().inspect(Collections.emptyList(),at)); }

    @Test void findsLeafInBothStoreFormatsWithoutEntryPassword() throws Exception {
        for(String type:Arrays.asList("JKS","PKCS12")) {
            Path file="JKS".equals(type)?jks:p12;
            KeyStore store=KeyStore.getInstance(type);
            try(InputStream in=Files.newInputStream(file)) { store.load(in,password()); }
            X509Certificate target=(X509Certificate)store.getCertificate("server");
            char[] callerPassword=password();
            List<CertificateMatch> matches=new KeyStoreCertificateFinder(analyzer(at)).find(file,type,callerPassword,target);
            assertEquals(1,matches.size());
            CertificateMatch match=matches.get(0);
            assertEquals("server",match.getAlias()); assertEquals("PRIVATE_KEY",match.getEntryType());
            assertEquals(0,match.getChainIndex()); assertNotNull(match.getCreationTime());
            assertEquals(analyzer(at).analyze(target).getDetails(),match.getCertificateReport().getDetails());
            assertArrayEquals(password(),callerPassword);
            assertThrows(UnsupportedOperationException.class,()->matches.clear());
        }
    }
    @Test void findsAllAliasesAndDeeperChainPositions() throws Exception {
        KeyStore source=KeyStore.getInstance("PKCS12");
        try(InputStream in=Files.newInputStream(p12)) { source.load(in,password()); }
        X509Certificate leaf=(X509Certificate)source.getCertificate("server");
        KeyStore store=KeyStore.getInstance("JKS"); store.load(null,password());
        store.setCertificateEntry("a-trusted",certificate);
        store.setCertificateEntry("b-trusted",certificate);
        // Deliberately synthetic chain: lookup must inspect positions regardless of chain trust.
        store.setKeyEntry("c-key",source.getKey("server",password()),"different-entry-password".toCharArray(),
            new java.security.cert.Certificate[]{leaf,certificate});
        Path file=directory.resolve("search-duplicates.jks");
        try(OutputStream out=Files.newOutputStream(file)) { store.store(out,password()); }
        List<CertificateMatch> matches=new KeyStoreCertificateFinder().find(file,"JKS",password(),certificate);
        assertEquals(3,matches.size());
        assertEquals("a-trusted",matches.get(0).getAlias()); assertEquals("b-trusted",matches.get(1).getAlias());
        assertEquals("TRUSTED_CERTIFICATE",matches.get(0).getEntryType()); assertEquals(-1,matches.get(0).getChainIndex());
        assertEquals("c-key",matches.get(2).getAlias()); assertEquals(1,matches.get(2).getChainIndex());
    }
    @Test void sameSubjectDoesNotMeanExactCertificateMatch() throws Exception {
        KeyStore other=KeyStore.getInstance("PKCS12");
        try(InputStream in=Files.newInputStream(p12)) { other.load(in,password()); }
        X509Certificate target=(X509Certificate)other.getCertificate("server");
        assertEquals(certificate.getSubjectX500Principal(),target.getSubjectX500Principal());
        assertTrue(new KeyStoreCertificateFinder().find(jks,"JKS",password(),target).isEmpty());
    }
    @Test void emptyAndSecretOnlyStoresReturnNoMatches() throws Exception {
        for(boolean secret:Arrays.asList(false,true)) {
            KeyStore store=KeyStore.getInstance("PKCS12");store.load(null,password());
            if(secret) store.setEntry("secret",new KeyStore.SecretKeyEntry(new javax.crypto.spec.SecretKeySpec(new byte[16],"AES")),new KeyStore.PasswordProtection(password()));
            Path file=directory.resolve("search-"+secret+".p12");
            try(OutputStream out=Files.newOutputStream(file)) { store.store(out,password()); }
            assertTrue(new KeyStoreCertificateFinder().find(file,"PKCS12",password(),certificate).isEmpty());
        }
    }
    @Test void searchRejectsWrongPasswordAndInvalidInputs() {
        KeyStoreCertificateFinder finder=new KeyStoreCertificateFinder();
        assertThrows(IOException.class,()->finder.find(jks,"JKS","wrong".toCharArray(),certificate));
        assertThrows(NullPointerException.class,()->finder.find(jks,"JKS",null,certificate));
        assertThrows(NullPointerException.class,()->finder.find(jks,"JKS",password(),null));
        assertThrows(IllegalArgumentException.class,()->finder.find(jks,"INVALID",password(),certificate));
        assertThrows(IOException.class,()->finder.find(directory.resolve("missing"),"JKS",password(),certificate));
    }
}
