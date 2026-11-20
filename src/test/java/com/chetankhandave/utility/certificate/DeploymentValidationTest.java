package com.chetankhandave.utility.certificate;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import com.google.gson.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;
import static org.junit.jupiter.api.Assertions.*;

/** Real signed fixtures exercise deployment policies without private production keys or network calls. */
class DeploymentValidationTest {
    static final Instant AT=Instant.parse("2030-01-01T00:00:00Z");
    static final String DNS="api.example.test", EKU="1.3.6.1.5.5.7.3.1";
    static KeyPair rootKey,issuerKey,leafKey,rotatedKey;
    static X509Certificate root,issuer,oldLeaf,newLeaf;
    static long serial;
    @TempDir Path directory;

    /** Creates a valid root/intermediate hierarchy and a same-key renewed leaf at fixed dates. */
    @BeforeAll static void fixtures() throws Exception {
        KeyPairGenerator gen=KeyPairGenerator.getInstance("RSA");gen.initialize(2048);
        rootKey=gen.generateKeyPair();issuerKey=gen.generateKeyPair();leafKey=gen.generateKeyPair();rotatedKey=gen.generateKeyPair();
        root=cert("CN=Root","CN=Root",rootKey.getPublic(),rootKey.getPrivate(),-30,1500,3,KeyUsage.keyCertSign|KeyUsage.cRLSign,null);
        issuer=cert("CN=Issuer","CN=Root",issuerKey.getPublic(),rootKey.getPrivate(),-20,1000,0,KeyUsage.keyCertSign|KeyUsage.cRLSign,null);
        oldLeaf=leaf(leafKey, -10,30,DNS,KeyUsage.digitalSignature|KeyUsage.keyEncipherment,true,"CN=Service");
        newLeaf=leaf(leafKey, -1,365,DNS,KeyUsage.digitalSignature|KeyUsage.keyEncipherment,true,"CN=Service");
    }
    /** Builds deterministic X.509 certificates with explicit constraints, usages and optional SAN/EKU. */
    static X509Certificate cert(String subject,String issuerName,PublicKey key,PrivateKey signer,long start,long end,int ca,int usage,String dns) throws Exception {
        return build(subject,issuerName,key,signer,start,end,ca,usage,dns,true);
    }
    /** Issues a leaf under the fixture intermediate with caller-controlled policy characteristics. */
    static X509Certificate leaf(KeyPair key,long start,long end,String dns,int usage,boolean eku,String subject) throws Exception {
        return build(subject,"CN=Issuer",key.getPublic(),issuerKey.getPrivate(),start,end,-1,usage,dns,eku);
    }
    /** Negative usage means the extension is absent, testing the conservative explicit-extension policy. */
    static X509Certificate build(String subject,String issuerName,PublicKey key,PrivateKey signer,long start,long end,int ca,int usage,String dns,boolean eku) throws Exception {
        JcaX509v3CertificateBuilder b=new JcaX509v3CertificateBuilder(new X500Name(issuerName),BigInteger.valueOf(++serial),
            Date.from(AT.plus(Duration.ofDays(start))),Date.from(AT.plus(Duration.ofDays(end))),new X500Name(subject),key);
        b.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints,true,ca<0?new BasicConstraints(false):new BasicConstraints(ca));
        if(usage>=0)b.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage,true,new KeyUsage(usage));
        if(dns!=null)b.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName,false,new GeneralNames(new GeneralName(GeneralName.dNSName,dns)));
        if(ca<0 && eku)b.addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage,false,new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        return new JcaX509CertificateConverter().getCertificate(b.build(new JcaContentSignerBuilder("SHA256withRSA").build(signer)));
    }
    /** Baseline policy deliberately checks DNS, usages, purpose, expiry advancement and unchanged public key. */
    static RenewalPolicy policy() {
        return RenewalPolicy.builder().requireDnsName(DNS).requireKeyUsage(0).requireEku(EKU)
            .publicKeyRule(RenewalPolicy.PublicKeyRule.MUST_REMAIN).build();
    }
    /** Convenient fixed-time validator avoids tests that depend on the wall clock. */
    static ValidationResult renew(X509Certificate old,X509Certificate current,RenewalPolicy policy) throws Exception {
        return new RenewalValidator(old,current,policy,AT).validate();
    }
    /** Locates a rule outcome so tests explain which requirement failed rather than only overall status. */
    static ValidationStatus rule(ValidationResult result,String id) {
        return result.getFindings().stream().filter(f->f.getRuleId().equals(id)).findFirst().get().getStatus();
    }
    /** Minimal synthetic comparison isolates expected-change policy tests from file format details. */
    static KeyStoreComparison comparison(String alias,KeyStoreComparison.Status status) {
        return new KeyStoreComparison(Arrays.asList(new KeyStoreComparison.Entry(alias,status,Collections.emptyList(),Collections.emptyList(),Collections.emptyList())),Collections.emptyList());
    }
    /** Builds an exact single-alias permission; an empty map means deny all modifications. */
    static ExpectedChangePolicy allowed(KeyStoreComparison.Status status) {
        Map<String,Set<KeyStoreComparison.Status>> map=new HashMap<>();map.put("server",EnumSet.of(status));
        return new ExpectedChangePolicy(map,Collections.emptyMap(),Collections.emptySet());
    }
    /** All actual modification kinds are accepted only when explicitly allowlisted for that alias. */
    @ParameterizedTest @EnumSource(value=KeyStoreComparison.Status.class,names={"ADDED","REMOVED","CHANGED","METADATA_CHANGED"})
    void approvesOnlyExplicitChangeKinds(KeyStoreComparison.Status status) {
        assertEquals(ValidationStatus.PASS,new ExpectedChangeValidator(comparison("server",status),allowed(status)).validate().getStatus());
        assertEquals(ValidationStatus.FAIL,new ExpectedChangeValidator(comparison("other",status),allowed(status)).validate().getStatus());
    }
    /** A certificate replacement permission must not accidentally approve a removal or metadata-only edit. */
    @Test void rejectsDifferentChangeKind() {
        assertEquals(ValidationStatus.FAIL,new ExpectedChangeValidator(comparison("server",KeyStoreComparison.Status.REMOVED),allowed(KeyStoreComparison.Status.CHANGED)).validate().getStatus());
        assertEquals(ValidationStatus.FAIL,new ExpectedChangeValidator(comparison("server",KeyStoreComparison.Status.METADATA_CHANGED),allowed(KeyStoreComparison.Status.CHANGED)).validate().getStatus());
    }
    /** A mandatory renewal fails if the alias is unchanged, missing, or changed in an unapproved way. */
    @Test void requiredChangesMustActuallyOccur() {
        Map<String,Set<KeyStoreComparison.Status>> map=new HashMap<>();map.put("server",EnumSet.of(KeyStoreComparison.Status.CHANGED));
        ExpectedChangePolicy p=new ExpectedChangePolicy(map,map,Collections.singleton("server"));
        assertEquals(ValidationStatus.FAIL,new ExpectedChangeValidator(comparison("server",KeyStoreComparison.Status.UNCHANGED),p).validate().getStatus());
        assertEquals(ValidationStatus.PASS,new ExpectedChangeValidator(comparison("server",KeyStoreComparison.Status.CHANGED),p).validate().getStatus());
        assertEquals(ValidationStatus.FAIL,new ExpectedChangeValidator(comparison("other",KeyStoreComparison.Status.UNCHANGED),p).validate().getStatus());
    }
    /** Removed aliases cannot satisfy a new-store required-alias requirement even if removal is approved. */
    @Test void requiredAliasCannotBeRemoved() {
        Map<String,Set<KeyStoreComparison.Status>> map=new HashMap<>();map.put("server",EnumSet.of(KeyStoreComparison.Status.REMOVED));
        ValidationResult result=new ExpectedChangeValidator(comparison("server",KeyStoreComparison.Status.REMOVED),new ExpectedChangePolicy(map,Collections.emptyMap(),Collections.singleton("server"))).validate();
        assertEquals(ValidationStatus.FAIL,rule(result,"required-alias.server"));
    }
    /** Unchanged public entries pass deny-all-change policy, but secret contents remain unchecked. */
    @Test void unchangedAndUncomparableRemainDistinct() {
        ExpectedChangePolicy p=new ExpectedChangePolicy(Collections.emptyMap(),Collections.emptyMap(),Collections.emptySet());
        assertEquals(ValidationStatus.PASS,new ExpectedChangeValidator(comparison("server",KeyStoreComparison.Status.UNCHANGED),p).validate().getStatus());
        assertEquals(ValidationStatus.NOT_CHECKED,new ExpectedChangeValidator(comparison("secret",KeyStoreComparison.Status.NOT_COMPARABLE),p).validate().getStatus());
    }
    /** Policy copies caller collections and rejects contradictory mandatory versus allowed statuses. */
    @Test void expectedPolicyIsDefensiveAndRejectsInvalidConfiguration() {
        Map<String,Set<KeyStoreComparison.Status>> map=new HashMap<>();Set<KeyStoreComparison.Status> set=EnumSet.of(KeyStoreComparison.Status.CHANGED);map.put("server",set);
        ExpectedChangePolicy p=new ExpectedChangePolicy(map,Collections.emptyMap(),Collections.emptySet());set.clear();map.clear();
        assertEquals(ValidationStatus.PASS,new ExpectedChangeValidator(comparison("server",KeyStoreComparison.Status.CHANGED),p).validate().getStatus());
        assertThrows(IllegalArgumentException.class,()->allowed(KeyStoreComparison.Status.UNCHANGED));
        assertThrows(IllegalArgumentException.class,()->allowed(KeyStoreComparison.Status.NOT_COMPARABLE));
        assertThrows(IllegalArgumentException.class,()->new ExpectedChangePolicy(Collections.emptyMap(),Collections.singletonMap("server",EnumSet.of(KeyStoreComparison.Status.CHANGED)),Collections.emptySet()));
    }
    /** A same-key renewal meeting all explicit requirements succeeds without proving trust. */
    @Test void validRenewalPasses() throws Exception { assertEquals(ValidationStatus.PASS,renew(oldLeaf,newLeaf,policy()).getStatus()); }
    /** Rotation can be required, forbidden, or unrestricted; certificate identity does not substitute for key identity. */
    @Test void publicKeyRotationPolicies() throws Exception {
        X509Certificate rotated=leaf(rotatedKey,-1,365,DNS,KeyUsage.digitalSignature,true,"CN=Service");
        RenewalPolicy requireChange=RenewalPolicy.builder().publicKeyRule(RenewalPolicy.PublicKeyRule.MUST_CHANGE).build();
        assertEquals(ValidationStatus.PASS,renew(oldLeaf,rotated,requireChange).getStatus());
        assertEquals(ValidationStatus.FAIL,rule(renew(oldLeaf,newLeaf,requireChange),"renewal.public-key"));
        assertEquals(ValidationStatus.FAIL,rule(renew(oldLeaf,rotated,policy()),"renewal.public-key"));
    }
    /** Expired and not-yet-valid replacements fail independently of other renewal requirements. */
    @Test void invalidValidityPeriodsFail() throws Exception {
        assertEquals(ValidationStatus.FAIL,rule(renew(oldLeaf,leaf(leafKey,-10,-1,DNS,KeyUsage.digitalSignature,true,"CN=Service"),policy()),"renewal.validity"));
        assertEquals(ValidationStatus.FAIL,rule(renew(oldLeaf,leaf(leafKey,1,365,DNS,KeyUsage.digitalSignature,true,"CN=Service"),policy()),"renewal.validity"));
    }
    /** Minimum remaining validity is inclusive at the exact boundary and fails one second beyond it. */
    @Test void remainingValidityBoundary() throws Exception {
        RenewalPolicy p=RenewalPolicy.builder().minimumRemaining(Duration.ofDays(365)).build();
        assertEquals(ValidationStatus.PASS,rule(renew(oldLeaf,newLeaf,p),"renewal.remaining"));
        assertEquals(ValidationStatus.FAIL,rule(new RenewalValidator(oldLeaf,newLeaf,p,AT.plusSeconds(1)).validate(),"renewal.remaining"));
    }
    /** X.509 notBefore/notAfter endpoints are valid, provided minimum remaining validity is zero. */
    @Test void validityEndpointsAreInclusive() throws Exception {
        RenewalPolicy p=RenewalPolicy.builder().minimumRemaining(Duration.ZERO).requireLaterExpiry(false).build();
        assertEquals(ValidationStatus.PASS,rule(new RenewalValidator(newLeaf,newLeaf,p,newLeaf.getNotBefore().toInstant()).validate(),"renewal.validity"));
        assertEquals(ValidationStatus.PASS,rule(new RenewalValidator(newLeaf,newLeaf,p,newLeaf.getNotAfter().toInstant()).validate(),"renewal.validity"));
    }
    /** Missing DNS SANs cannot be satisfied by the subject CN or a wildcard under exact-SAN policy. */
    @Test void exactDnsRejectsMissingWrongAndWildcardSans() throws Exception {
        for(String dns:Arrays.asList(null,"wrong.example.test","*.example.test"))
            assertEquals(ValidationStatus.FAIL,rule(renew(oldLeaf,leaf(leafKey,-1,365,dns,KeyUsage.digitalSignature,true,"CN="+DNS),policy()),"renewal.dns."+DNS));
    }
    /** DNS comparison ignores case/trailing dots and normalizes international names using IDN. */
    @Test void dnsNormalizationIsExplicit() throws Exception {
        assertEquals(ValidationStatus.PASS,rule(renew(oldLeaf,newLeaf,RenewalPolicy.builder().requireDnsName("API.EXAMPLE.TEST.").build()),"renewal.dns."+DNS));
        assertEquals("xn--bcher-kva.example",RenewalPolicy.dns("bücher.example"));
        assertThrows(IllegalArgumentException.class,()->RenewalPolicy.builder().requireDnsName("*.example.test"));
    }
    /** Missing or incompatible explicit KU/EKU extensions fail conservative purpose policy. */
    @Test void requiredExtensionsMustBePresentAndPermitPurpose() throws Exception {
        X509Certificate absent=leaf(leafKey,-1,365,DNS,-1,false,"CN=Service");
        assertEquals(ValidationStatus.FAIL,rule(renew(oldLeaf,absent,policy()),"renewal.ku.0"));
        assertEquals(ValidationStatus.FAIL,rule(renew(oldLeaf,absent,policy()),"renewal.eku."+EKU));
        assertEquals(ValidationStatus.FAIL,rule(renew(oldLeaf,leaf(leafKey,-1,365,DNS,KeyUsage.keyEncipherment,true,"CN=Service"),policy()),"renewal.ku.0"));
        assertEquals(ValidationStatus.FAIL,rule(renew(oldLeaf,newLeaf,RenewalPolicy.builder().requireEku("1.3.6.1.5.5.7.3.2").build()),"renewal.eku.1.3.6.1.5.5.7.3.2"));
    }
    /** Subject preservation, later expiry and end-entity constraints are separate configurable requirements. */
    @Test void renewalStructuralRequirements() throws Exception {
        assertEquals(ValidationStatus.FAIL,rule(renew(oldLeaf,leaf(leafKey,-1,365,DNS,KeyUsage.digitalSignature,true,"CN=Different"),policy()),"renewal.subject"));
        assertEquals(ValidationStatus.FAIL,rule(renew(newLeaf,newLeaf,policy()),"renewal.later-expiry"));
        assertEquals(ValidationStatus.FAIL,rule(renew(oldLeaf,root,policy()),"renewal.end-entity"));
        assertEquals(ValidationStatus.PASS,renew(newLeaf,newLeaf,RenewalPolicy.builder().requireLaterExpiry(false).build()).getStatus());
    }
    /** A missing new certificate fails, while a missing required baseline is explicitly unchecked. */
    @Test void missingRenewalInputsDoNotPass() throws Exception {
        assertEquals(ValidationStatus.FAIL,renew(oldLeaf,null,policy()).getStatus());
        assertEquals(ValidationStatus.NOT_CHECKED,renew(null,newLeaf,policy()).getStatus());
        assertEquals(ValidationStatus.PASS,renew(null,newLeaf,RenewalPolicy.builder().requireLaterExpiry(false).preserveSubject(false).build()).getStatus());
    }
    /** Invalid builder arguments fail immediately and subsequent builder edits cannot mutate built policy. */
    @Test void renewalPolicyBoundariesAndDefensiveBuild() throws Exception {
        assertThrows(IllegalArgumentException.class,()->RenewalPolicy.builder().minimumRemaining(Duration.ofSeconds(-1)));
        assertThrows(IllegalArgumentException.class,()->RenewalPolicy.builder().requireKeyUsage(-1));
        assertThrows(IllegalArgumentException.class,()->RenewalPolicy.builder().requireKeyUsage(9));
        assertThrows(IllegalArgumentException.class,()->RenewalPolicy.builder().requireEku("invalid"));
        assertThrows(NullPointerException.class,()->RenewalPolicy.builder().publicKeyRule(null));
        RenewalPolicy.Builder b=RenewalPolicy.builder();RenewalPolicy p=b.build();b.requireDnsName("missing.example");
        assertEquals(ValidationStatus.PASS,renew(oldLeaf,newLeaf,p).getStatus());
    }
    /** Fixed root and candidate lists simplify trust cases without silently consulting system roots. */
    static ValidationResult trust(X509Certificate leaf,List<X509Certificate> candidates,X509Certificate anchor,TruststoreValidator.Revocation revocation) throws Exception {
        return new TruststoreValidator(leaf,candidates,anchor==null?Collections.emptyMap():Collections.singletonMap("root",anchor),AT,revocation).validate();
    }
    /** PKIX builds a path from an unordered candidate collection and reports the selected approved alias. */
    @Test void buildsUnorderedChainToExplicitAnchor() throws Exception {
        ValidationResult result=trust(newLeaf,Arrays.asList(root,newLeaf,issuer),root,TruststoreValidator.Revocation.DISABLED);
        assertEquals(ValidationStatus.PASS,result.getStatus());assertEquals(ValidationStatus.PASS,rule(result,"trust.path"));
        assertEquals(ValidationStatus.NOT_CHECKED,rule(result,"trust.revocation"));
        assertTrue(result.getFindings().stream().anyMatch(f->f.getMessage().contains("anchor alias: root")));
    }
    /** A missing intermediate and a valid chain to an unapproved root both fail path construction. */
    @Test void missingIntermediateAndUntrustedRootFail() throws Exception {
        assertEquals(ValidationStatus.FAIL,rule(trust(newLeaf,Collections.emptyList(),root,TruststoreValidator.Revocation.DISABLED),"trust.path"));
        X509Certificate other=cert("CN=Other","CN=Other",rotatedKey.getPublic(),rotatedKey.getPrivate(),-30,1500,3,KeyUsage.keyCertSign,null);
        assertEquals(ValidationStatus.FAIL,rule(trust(newLeaf,Arrays.asList(root,issuer),other,TruststoreValidator.Revocation.DISABLED),"trust.path"));
    }
    /** A matching issuer name cannot hide an invalid signature or an expired issuer certificate. */
    @Test void badSignatureAndExpiredIssuerFailPkix() throws Exception {
        X509Certificate forged=build("CN=Service","CN=Issuer",leafKey.getPublic(),rotatedKey.getPrivate(),-1,365,-1,KeyUsage.digitalSignature,DNS,true);
        assertEquals(ValidationStatus.FAIL,rule(trust(forged,Arrays.asList(issuer),root,TruststoreValidator.Revocation.DISABLED),"trust.path"));
        X509Certificate expired=cert("CN=Issuer","CN=Root",issuerKey.getPublic(),rootKey.getPrivate(),-20,-1,0,KeyUsage.keyCertSign,null);
        assertEquals(ValidationStatus.FAIL,rule(trust(newLeaf,Arrays.asList(expired),root,TruststoreValidator.Revocation.DISABLED),"trust.path"));
    }
    /** Local trust policy rejects non-CA, expired and not-yet-valid anchors, plus missing leaf/anchors. */
    @Test void trustAnchorAndLeafPreconditions() throws Exception {
        assertEquals(ValidationStatus.FAIL,trust(newLeaf,Arrays.asList(issuer),newLeaf,TruststoreValidator.Revocation.DISABLED).getStatus());
        X509Certificate expired=cert("CN=Root","CN=Root",rootKey.getPublic(),rootKey.getPrivate(),-30,-1,3,KeyUsage.keyCertSign,null);
        assertEquals(ValidationStatus.FAIL,trust(newLeaf,Arrays.asList(issuer),expired,TruststoreValidator.Revocation.DISABLED).getStatus());
        assertEquals(ValidationStatus.FAIL,trust(null,Collections.emptyList(),root,TruststoreValidator.Revocation.DISABLED).getStatus());
        assertEquals(ValidationStatus.FAIL,trust(newLeaf,Collections.emptyList(),null,TruststoreValidator.Revocation.DISABLED).getStatus());
        X509Certificate expiredLeaf=leaf(leafKey,-5,-1,DNS,KeyUsage.digitalSignature,true,"CN=Service");
        assertEquals(ValidationStatus.FAIL,trust(expiredLeaf,Arrays.asList(issuer),root,TruststoreValidator.Revocation.DISABLED).getStatus());
    }
    /** Revocation cannot pass when policy requires it but no revocation mechanism is configured. */
    @Test void requiredRevocationBlocksOtherwiseValidPath() throws Exception {
        ValidationResult result=trust(newLeaf,Arrays.asList(issuer),root,TruststoreValidator.Revocation.REQUIRED);
        assertEquals(ValidationStatus.PASS,rule(result,"trust.path"));assertEquals(ValidationStatus.NOT_CHECKED,result.getStatus());
    }
    /** Stores generated with separate entry passwords prove validators need only store passwords. */
    Path store(String name,String type,X509Certificate leaf,boolean trustedRoot) throws Exception {
        KeyStore store=KeyStore.getInstance(type);store.load(null,password());
        if(leaf!=null)store.setKeyEntry("server",leafKey.getPrivate(),"entry-only-secret".toCharArray(),new java.security.cert.Certificate[]{leaf,issuer,root});
        if(trustedRoot)store.setCertificateEntry("root",root);
        Path file=directory.resolve(name);try(OutputStream output=Files.newOutputStream(file)) { store.store(output,password()); }return file;
    }
    /** Password arrays are fresh and test-only, never reused as production credentials. */
    static char[] password() { return "store-only-secret".toCharArray(); }
    /** Complete policy permits the server renewal and one harmless metadata-only change kind. */
    static Properties properties() {
        Properties p=new Properties();p.setProperty("target.alias","server");p.setProperty("trust.anchorAliases","root");
        p.setProperty("allowChange.server","CHANGED,METADATA_CHANGED");p.setProperty("requireChange.server","CHANGED");
        p.setProperty("requiredAliases","server");p.setProperty("renewal.requiredDnsNames",DNS);
        p.setProperty("renewal.requiredKeyUsage","0");p.setProperty("renewal.requiredEku",EKU);p.setProperty("renewal.publicKey","MUST_REMAIN");return p;
    }
    /** Only selected trusted-certificate entries may be promoted to anchors; key entries are rejected. */
    @Test void anchorLoadingRequiresExplicitTrustedAliases() throws Exception {
        for(String type:Arrays.asList("JKS","PKCS12")) {
            Path file=store("anchors-"+type,type,newLeaf,true);char[] caller=password();
            assertEquals(root,TruststoreValidator.readAnchors(file,type,caller,Collections.singleton("root")).get("root"));
            assertArrayEquals(password(),caller);
            assertThrows(KeyStoreException.class,()->TruststoreValidator.readAnchors(file,type,password(),Collections.singleton("server")));
            assertThrows(KeyStoreException.class,()->TruststoreValidator.readAnchors(file,type,password(),Collections.singleton("missing")));
            assertThrows(IllegalArgumentException.class,()->TruststoreValidator.readAnchors(file,type,password(),Collections.emptySet()));
            assertThrows(IOException.class,()->TruststoreValidator.readAnchors(file,type,"wrong".toCharArray(),Collections.singleton("root")));
        }
    }
    /** All three checks succeed for a real same-key renewal, for both supported store formats. */
    @Test void integratedValidationWorksForJksAndPkcs12() throws Exception {
        for(String type:Arrays.asList("JKS","PKCS12")) {
            Path before=store("old-"+type,type,oldLeaf,false),after=store("new-"+type,type,newLeaf,false),trust=store("trust-"+type,type,null,true);
            char[] oldPassword=password();
            DeploymentValidationReport report=new DeploymentValidationService(Clock.fixed(AT,ZoneOffset.UTC)).validate(before,type,oldPassword,after,type,password(),trust,type,password(),DeploymentValidationPolicy.fromProperties(properties()));
            assertEquals(3,report.getResults().size());assertEquals(ValidationStatus.PASS,report.getStatus());assertArrayEquals(password(),oldPassword);
            for(ComparisonReportFormat format:ComparisonReportFormat.values())assertTrue(new DeploymentValidationReportFormatter().format(report,format).contains("PASS"));
            JsonObject json=JsonParser.parseString(new DeploymentValidationReportFormatter().format(report,ComparisonReportFormat.JSON)).getAsJsonObject();
            assertEquals("PASS",json.getAsJsonObject("validation").get("status").getAsString());assertTrue(json.has("comparison"));
            assertTrue(json.getAsJsonObject("validation").getAsJsonArray("checks").get(0).getAsJsonObject().getAsJsonArray("findings").get(0).getAsJsonObject().get("required").getAsJsonPrimitive().isBoolean());
        }
    }
    /** A truststore password error yields ERROR for trust without suppressing the other two outcomes. */
    @Test void truststoreIoFailureDoesNotHideOtherResults() throws Exception {
        Path before=store("io-old","JKS",oldLeaf,false),after=store("io-new","JKS",newLeaf,false),trust=store("io-trust","JKS",null,true);
        DeploymentValidationReport report=new DeploymentValidationService(Clock.fixed(AT,ZoneOffset.UTC)).validate(before,"JKS",password(),after,"JKS",password(),trust,"JKS","wrong".toCharArray(),DeploymentValidationPolicy.fromProperties(properties()));
        assertEquals(ValidationStatus.PASS,report.getResults().get(0).getStatus());assertEquals(ValidationStatus.PASS,report.getResults().get(1).getStatus());
        assertEquals(ValidationStatus.ERROR,report.getResults().get(2).getStatus());assertEquals(ValidationStatus.ERROR,report.getStatus());
    }
    /** Invalid configuration is rejected instead of silently disabling intended deployment controls. */
    @Test void propertiesRejectUnknownKeysAndMalformedValues() {
        Properties p=properties();p.setProperty("renewal.typo","true");assertThrows(IllegalArgumentException.class,()->DeploymentValidationPolicy.fromProperties(p));
        for(String[] pair:new String[][]{{"renewal.requireLaterExpiry","maybe"},{"renewal.minimumRemainingDays","-1"},{"renewal.requiredKeyUsage","9"},{"trust.revocation","soft"},{"renewal.requiredDnsNames","a,,b"},{"allowChange.server","UNCHANGED"},{"target.alias",""},{"trust.anchorAliases",""}}) {
            Properties invalid=properties();invalid.setProperty(pair[0],pair[1]);assertThrows(IllegalArgumentException.class,()->DeploymentValidationPolicy.fromProperties(invalid));
        }
    }
    /** Execution errors are isolated and their exception messages cannot leak supplied secret strings. */
    @Test void coordinatorContinuesAfterExceptionsAndNullResults() {
        ValidationCheck broken=new ValidationCheck() { public String getName(){return "broken";}public ValidationResult validate(){throw new IllegalStateException("password=secret");} };
        ValidationCheck good=new ValidationCheck() { public String getName(){return "good";}public ValidationResult validate(){return new ValidationResult(getName(),Arrays.asList(ValidationFinding.test("ok",true,"ok")));} };
        ValidationCheck missing=new ValidationCheck() { public String getName(){return "missing";}public ValidationResult validate(){return null;} };
        List<ValidationResult> results=new ValidationCoordinator().run(Arrays.asList(broken,missing,good));
        assertEquals(ValidationStatus.ERROR,results.get(0).getStatus());assertEquals(ValidationStatus.ERROR,results.get(1).getStatus());
        assertEquals(ValidationStatus.PASS,results.get(2).getStatus());
        assertFalse(results.get(0).getFindings().get(0).getMessage().contains("secret"));
        assertThrows(UnsupportedOperationException.class,()->results.clear());
    }
    /** ERROR dominates FAIL, required unchecked blocks PASS, and optional unchecked revocation stays visible. */
    @Test void aggregationHasFailClosedPrecedence() {
        List<ValidationFinding> findings=new ArrayList<>();findings.add(ValidationFinding.test("pass",true,"ok"));
        findings.add(new ValidationFinding("optional",ValidationStatus.NOT_CHECKED,"disabled",false));
        assertEquals(ValidationStatus.PASS,new ValidationResult("test",findings).getStatus());
        findings.add(new ValidationFinding("required",ValidationStatus.NOT_CHECKED,"missing",true));assertEquals(ValidationStatus.NOT_CHECKED,new ValidationResult("test",findings).getStatus());
        findings.add(ValidationFinding.test("fail",false,"no"));assertEquals(ValidationStatus.FAIL,new ValidationResult("test",findings).getStatus());
        findings.add(new ValidationFinding("error",ValidationStatus.ERROR,"error",true));assertEquals(ValidationStatus.ERROR,new ValidationResult("test",findings).getStatus());
        assertEquals(ValidationStatus.NOT_CHECKED,new ValidationResult("empty",Collections.emptyList()).getStatus());
    }
    /** New result collections are immutable and retain their original contents after caller mutation. */
    @Test void validationReportsAreDefensive() {
        List<ValidationFinding> findings=new ArrayList<>();findings.add(ValidationFinding.test("ok",true,"ok"));
        ValidationResult result=new ValidationResult("name",findings);findings.clear();assertEquals(1,result.getFindings().size());
        List<ValidationResult> results=new ArrayList<>();results.add(result);
        DeploymentValidationReport report=new DeploymentValidationReport(comparison("a",KeyStoreComparison.Status.UNCHANGED),results);results.clear();
        assertEquals(ValidationStatus.PASS,report.getStatus());assertThrows(UnsupportedOperationException.class,()->report.getResults().clear());
        assertThrows(UnsupportedOperationException.class,()->result.getFindings().clear());
    }
    /** HTML escapes validation names/rule IDs/messages, and JSON retains exact original text. */
    @Test void combinedReportEscapesValidationPayloads() throws Exception {
        String payload="</main><script>alert('x')</script> & \"quoted\"";
        ValidationResult result=new ValidationResult(payload,Arrays.asList(new ValidationFinding(payload,ValidationStatus.FAIL,payload,true)));
        DeploymentValidationReport report=new DeploymentValidationReport(comparison("a",KeyStoreComparison.Status.UNCHANGED),Arrays.asList(result));
        DeploymentValidationReportFormatter formatter=new DeploymentValidationReportFormatter();
        DocumentBuilderFactory factory=DocumentBuilderFactory.newInstance();factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd",false);
        org.w3c.dom.Document html=factory.newDocumentBuilder().parse(new InputSource(new StringReader(formatter.format(report,ComparisonReportFormat.HTML))));
        assertEquals(0,html.getElementsByTagName("script").getLength());assertTrue(html.getDocumentElement().getTextContent().contains(payload));
        JsonObject json=JsonParser.parseString(formatter.format(report,ComparisonReportFormat.JSON)).getAsJsonObject();
        assertEquals(payload,json.getAsJsonObject("validation").getAsJsonArray("checks").get(0).getAsJsonObject().get("name").getAsString());
    }
    /** Immutable validators and local JCA objects support concurrent read-only validation. */
    @Test void validatorsCanRunConcurrently() throws Exception {
        RenewalValidator validator=new RenewalValidator(oldLeaf,newLeaf,policy(),AT);ExecutorService pool=Executors.newFixedThreadPool(4);
        try { List<Callable<ValidationStatus>> tasks=new ArrayList<>();for(int i=0;i<12;i++)tasks.add(()->validator.validate().getStatus());
            for(Future<ValidationStatus> result:pool.invokeAll(tasks))assertEquals(ValidationStatus.PASS,result.get());
        } finally { pool.shutdownNow(); }
    }
    /** CLI argument errors fail before opening stores or requesting passwords. */
    @Test void validationCliRejectsIncompleteArguments() { assertThrows(IllegalArgumentException.class,()->DeploymentValidationCli.main(new String[]{"validate"})); }

    /** A trusted renewal with an incorrect SAN still fails overall while the other checks pass. */
    @Test void integratedResultsRemainIndependentWhenRenewalFails() throws Exception {
        X509Certificate wrongDns=leaf(leafKey,-1,365,"wrong.example.test",KeyUsage.digitalSignature,true,"CN=Service");
        Path before=store("dns-old","JKS",oldLeaf,false),after=store("dns-new","JKS",wrongDns,false),trusted=store("dns-trust","JKS",null,true);
        DeploymentValidationReport report=new DeploymentValidationService(Clock.fixed(AT,ZoneOffset.UTC)).validate(before,"JKS",password(),after,"JKS",password(),trusted,"JKS",password(),DeploymentValidationPolicy.fromProperties(properties()));
        assertEquals(ValidationStatus.PASS,report.getResults().get(0).getStatus());assertEquals(ValidationStatus.FAIL,report.getResults().get(1).getStatus());
        assertEquals(ValidationStatus.PASS,report.getResults().get(2).getStatus());assertEquals(ValidationStatus.FAIL,report.getStatus());
    }
    /** Required revocation propagates as unchecked through the complete deployment workflow. */
    @Test void integratedRevocationRequirementCannotBeGreen() throws Exception {
        Path before=store("revoke-old","PKCS12",oldLeaf,false),after=store("revoke-new","PKCS12",newLeaf,false),trusted=store("revoke-trust","PKCS12",null,true);
        Properties p=properties();p.setProperty("trust.revocation","REQUIRED");
        DeploymentValidationReport report=new DeploymentValidationService(Clock.fixed(AT,ZoneOffset.UTC)).validate(before,"PKCS12",password(),after,"PKCS12",password(),trusted,"PKCS12",password(),DeploymentValidationPolicy.fromProperties(p));
        assertEquals(ValidationStatus.NOT_CHECKED,report.getStatus());
    }
    /** Non-CA intermediate and exceeded intermediate path-length constraints are enforced by PKIX. */
    @Test void pkixEnforcesIntermediateCaAndPathLength() throws Exception {
        X509Certificate notCa=cert("CN=Issuer","CN=Root",issuerKey.getPublic(),rootKey.getPrivate(),-20,1000,-1,KeyUsage.keyCertSign,null);
        assertEquals(ValidationStatus.FAIL,rule(trust(newLeaf,Arrays.asList(notCa),root,TruststoreValidator.Revocation.DISABLED),"trust.path"));
        X509Certificate extra=cert("CN=Extra","CN=Issuer",rotatedKey.getPublic(),issuerKey.getPrivate(),-10,500,0,KeyUsage.keyCertSign,null);
        X509Certificate extraLeaf=build("CN=Service","CN=Extra",leafKey.getPublic(),rotatedKey.getPrivate(),-1,365,-1,KeyUsage.digitalSignature,DNS,true);
        assertEquals(ValidationStatus.FAIL,rule(trust(extraLeaf,Arrays.asList(extra,issuer),root,TruststoreValidator.Revocation.DISABLED),"trust.path"));
    }
    /** Anchor certificate-signing permission and future validity are local explicit trust requirements. */
    @Test void anchorSigningUsageAndFutureValidityAreRejected() throws Exception {
        X509Certificate badUsage=cert("CN=Root","CN=Root",rootKey.getPublic(),rootKey.getPrivate(),-30,1500,3,KeyUsage.digitalSignature,null);
        X509Certificate future=cert("CN=Root","CN=Root",rootKey.getPublic(),rootKey.getPrivate(),1,1500,3,KeyUsage.keyCertSign,null);
        assertEquals(ValidationStatus.FAIL,trust(newLeaf,Arrays.asList(issuer),badUsage,TruststoreValidator.Revocation.DISABLED).getStatus());
        assertEquals(ValidationStatus.FAIL,trust(newLeaf,Arrays.asList(issuer),future,TruststoreValidator.Revocation.DISABLED).getStatus());
    }
    /** A future-validity leaf fails trust even if a correct issuer hierarchy is supplied. */
    @Test void trustRejectsNotYetValidLeaf() throws Exception {
        X509Certificate future=leaf(leafKey,1,365,DNS,KeyUsage.digitalSignature,true,"CN=Service");
        assertEquals(ValidationStatus.FAIL,trust(future,Arrays.asList(issuer),root,TruststoreValidator.Revocation.DISABLED).getStatus());
    }
    /** A report with no validators is unchecked, and null report inputs fail before serialization. */
    @Test void emptyAndNullDeploymentReportInputs() {
        DeploymentValidationReport report=new DeploymentValidationReport(comparison("a",KeyStoreComparison.Status.UNCHANGED),Collections.emptyList());
        assertEquals(ValidationStatus.NOT_CHECKED,report.getStatus());
        assertThrows(NullPointerException.class,()->new DeploymentValidationReportFormatter().format(null,ComparisonReportFormat.JSON));
        assertThrows(NullPointerException.class,()->new DeploymentValidationReportFormatter().format(report,null));
        assertThrows(NullPointerException.class,()->new ValidationFinding(null,ValidationStatus.PASS,"message",true));
    }
}
