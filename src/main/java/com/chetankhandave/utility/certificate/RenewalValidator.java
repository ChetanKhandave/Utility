package com.chetankhandave.utility.certificate;

import java.security.cert.*;
import java.time.*;
import java.util.*;

/** Checks a new certificate against explicit policy; trust is intentionally a separate validator. */
public final class RenewalValidator implements ValidationCheck {
    private final X509Certificate before,after;
    private final RenewalPolicy policy;
    private final Instant at;
    public RenewalValidator(X509Certificate before,X509Certificate after,RenewalPolicy policy,Instant at) {
        this.before=before;this.after=after;this.policy=Objects.requireNonNull(policy,"policy");this.at=Objects.requireNonNull(at,"at");
    }
    @Override public String getName() { return "renewal"; }
    @Override public ValidationResult validate() throws CertificateParsingException {
        List<ValidationFinding> f=new ArrayList<>();
        if(after==null) return new ValidationResult(getName(),Arrays.asList(ValidationFinding.test("renewal.present",false,"New X.509 certificate is missing")));
        Instant start=after.getNotBefore().toInstant(),end=after.getNotAfter().toInstant();
        f.add(ValidationFinding.test("renewal.validity",!at.isBefore(start) && !at.isAfter(end),"New certificate must be valid at "+at));
        f.add(ValidationFinding.test("renewal.remaining",Duration.between(at,end).compareTo(policy.minimumRemaining)>=0,"Minimum remaining validity: "+policy.minimumRemaining));
        if(policy.endEntity) f.add(ValidationFinding.test("renewal.end-entity",after.getBasicConstraints()<0,"An end-entity certificate is required"));
        Set<String> names=new TreeSet<>(); Collection<List<?>> sans=after.getSubjectAlternativeNames();
        if(sans!=null) for(List<?> san:sans) if(san.size()>=2 && Integer.valueOf(2).equals(san.get(0)) && san.get(1) instanceof String) {
            // Wildcard SANs are not accepted for exact-name policy; there is no CN fallback.
            try { names.add(RenewalPolicy.dns((String)san.get(1))); } catch(IllegalArgumentException ignored) { }
        }
        for(String name:policy.dnsNames) f.add(ValidationFinding.test("renewal.dns."+name,names.contains(name),"Required exact DNS SAN: "+name));
        boolean[] usage=after.getKeyUsage();
        for(int bit:policy.keyUsage) f.add(ValidationFinding.test("renewal.ku."+bit,usage!=null && usage.length>bit && usage[bit],"Required key usage bit: "+bit+" (extension must be present)"));
        List<String> eku=after.getExtendedKeyUsage();
        for(String oid:policy.ekuOids) f.add(ValidationFinding.test("renewal.eku."+oid,eku!=null && eku.contains(oid),"Required explicit EKU OID: "+oid));
        if(before==null && (policy.laterExpiry || policy.preserveSubject || policy.publicKeyRule!=RenewalPolicy.PublicKeyRule.ANY))
            f.add(new ValidationFinding("renewal.baseline",ValidationStatus.NOT_CHECKED,"Old certificate is required by comparison policy but is missing",true));
        if(before!=null) {
            if(policy.laterExpiry) f.add(ValidationFinding.test("renewal.later-expiry",end.isAfter(before.getNotAfter().toInstant()),"New expiry must be later than old expiry"));
            if(policy.preserveSubject) f.add(ValidationFinding.test("renewal.subject",before.getSubjectX500Principal().equals(after.getSubjectX500Principal()),"Subject must match old certificate"));
            if(policy.publicKeyRule!=RenewalPolicy.PublicKeyRule.ANY) {
                boolean same=Arrays.equals(before.getPublicKey().getEncoded(),after.getPublicKey().getEncoded());
                f.add(ValidationFinding.test("renewal.public-key",policy.publicKeyRule==RenewalPolicy.PublicKeyRule.MUST_REMAIN?same:!same,"Public key policy: "+policy.publicKeyRule));
            }
        }
        return new ValidationResult(getName(),f);
    }
}
