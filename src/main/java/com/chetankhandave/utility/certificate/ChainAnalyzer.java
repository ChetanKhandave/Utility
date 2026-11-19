package com.chetankhandave.utility.certificate;

import java.security.*;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;

/** Separates adjacent signature checks from PKIX trust-path validation. */
public final class ChainAnalyzer {
    /** Input must be leaf first. This does not establish trust or check revocation. */
    public AnalysisReport inspect(List<X509Certificate> chain, Instant at) {
        if(chain.isEmpty()) throw new IllegalArgumentException("Chain must not be empty");
        List<String> findings=new ArrayList<>();
        for(int i=0;i<chain.size();i++) {
            X509Certificate c=chain.get(i);
            try { c.checkValidity(Date.from(at)); }
            catch(CertificateException e) { findings.add("Certificate "+i+" outside validity period"); }
            if(i+1<chain.size()) {
                X509Certificate issuer=chain.get(i+1);
                if(!c.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) findings.add("Issuer mismatch at index "+i);
                try { c.verify(issuer.getPublicKey()); }
                catch(GeneralSecurityException e) { findings.add("Signature verification failed at index "+i); }
                if(issuer.getBasicConstraints()<0) findings.add("Issuer at index "+(i+1)+" is not a CA");
                boolean[] usage=issuer.getKeyUsage();
                if(usage!=null && (usage.length<=5 || !usage[5])) findings.add("Issuer lacks keyCertSign at index "+(i+1));
            }
        }
        Map<String,String> d=new LinkedHashMap<>();
        d.put("certificateCount",String.valueOf(chain.size()));
        d.put("trust", "NOT_EVALUATED");
        d.put("revocation", "NOT_CHECKED");
        return new AnalysisReport(d,findings);
    }
    /**
     * Validates an ordered path against explicit anchors using the JCA PKIX provider.
     * The trust anchor is removed from the path when included as the last certificate.
     * Revocation is intentionally disabled: no network OCSP/CRL requests are made.
     */
    public PKIXCertPathValidatorResult validate(List<X509Certificate> chain,
            Set<TrustAnchor> anchors, Instant at) throws GeneralSecurityException {
        if(chain.isEmpty() || anchors.isEmpty()) throw new IllegalArgumentException("Chain and trust anchors are required");
        List<X509Certificate> path=new ArrayList<>(chain);
        X509Certificate last=path.get(path.size()-1);
        for(TrustAnchor anchor:anchors) {
            if(last.equals(anchor.getTrustedCert())) { path.remove(path.size()-1); break; }
        }
        PKIXParameters params=new PKIXParameters(anchors);
        params.setDate(Date.from(at));
        params.setRevocationEnabled(false);
        CertPath certPath=CertificateFactory.getInstance("X.509").generateCertPath(path);
        return (PKIXCertPathValidatorResult)CertPathValidator.getInstance("PKIX").validate(certPath,params);
    }
}
