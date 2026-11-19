package com.chetankhandave.utility.certificate;

import java.io.IOException;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.*;
import java.util.*;

/** Exact DER certificate lookup across all aliases, including complete key-entry chains. */
public final class KeyStoreCertificateFinder {
    private final CertificateAnalyzer analyzer;
    public KeyStoreCertificateFinder() { this(new CertificateAnalyzer()); }
    public KeyStoreCertificateFinder(CertificateAnalyzer analyzer) {
        this.analyzer = Objects.requireNonNull(analyzer, "analyzer");
    }
    /**
     * Returns every occurrence sorted by alias then chain index; empty means absent.
     * Does not recover private keys, require entry passwords, or establish trust.
     * The caller retains ownership of storePassword and should clear it after use.
     */
    public List<CertificateMatch> find(Path file, String type, char[] storePassword,
            X509Certificate target) throws IOException, GeneralSecurityException {
        Objects.requireNonNull(target, "target");
        byte[] targetDer = target.getEncoded();
        KeyStore store = KeyStoreLoader.load(file, type, storePassword);
        List<String> aliases = Collections.list(store.aliases());
        Collections.sort(aliases);
        List<CertificateMatch> matches = new ArrayList<>();
        for (String alias : aliases) {
            java.security.cert.Certificate[] chain = store.getCertificateChain(alias);
            if (chain != null) {
                // Searching only getCertificate(alias) would miss intermediate/root certificates.
                for (int index = 0; index < chain.length; index++) {
                    addMatch(store, alias, "PRIVATE_KEY", index, chain[index], targetDer, matches);
                }
            } else if (store.isCertificateEntry(alias)) {
                addMatch(store, alias, "TRUSTED_CERTIFICATE", -1,
                    store.getCertificate(alias), targetDer, matches);
            }
        }
        return Collections.unmodifiableList(matches);
    }
    private void addMatch(KeyStore store, String alias, String entryType, int index,
            java.security.cert.Certificate candidate, byte[] targetDer,
            List<CertificateMatch> matches) throws GeneralSecurityException {
        // Exact bytes distinguish renewed certificates even when subject and public key match.
        if (candidate instanceof X509Certificate && Arrays.equals(targetDer, candidate.getEncoded())) {
            Date created = store.getCreationDate(alias);
            matches.add(new CertificateMatch(alias, entryType,
                created == null ? null : created.toInstant(), index,
                analyzer.analyze((X509Certificate) candidate)));
        }
    }
}
