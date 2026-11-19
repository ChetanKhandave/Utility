# Certificate and keystore analysis (Java 8+)

Read-only Java utility in `com.chetankhandave.utility.certificate`. Production code uses only standard JCA/JCE APIs: no runtime dependencies or internal `sun.security` APIs.

## Build and run

```sh
mvn clean test package
java -cp target/utility-1.0-SNAPSHOT.jar com.chetankhandave.utility.certificate.CertificateAnalysisCli certificate certificate.pem
java -cp target/utility-1.0-SNAPSHOT.jar com.chetankhandave.utility.certificate.CertificateAnalysisCli keystore JKS application.jks
java -cp target/utility-1.0-SNAPSHOT.jar com.chetankhandave.utility.certificate.CertificateAnalysisCli keystore PKCS12 application.p12
```

The keystore command requires an interactive terminal. It prompts for store and private-entry passwords without echoing them. Do not put passwords in command-line arguments. API callers can skip private-key recovery entirely by passing a null password provider.

## Java API

```java
import com.chetankhandave.utility.certificate.*;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.*;

CertificateAnalyzer analyzer = new CertificateAnalyzer();
List<X509Certificate> certificates = analyzer.read(Paths.get("certificate.pem"));
AnalysisReport report = analyzer.analyze(certificates.get(0));
System.out.println(report.getDetails());
System.out.println(report.getFindings());

// storePassword is a char[] obtained from your secret source.
// Caller owns and clears storePassword. Null skips private key recovery.
Map<String, List<AnalysisReport>> entries = new KeyStoreAnalyzer()
    .analyze(Paths.get("application.jks"), "JKS", storePassword, null);
```

To check private key/certificate correspondence, supply a `KeyPasswordProvider` that returns a **fresh password array** for each alias. The analyzer clears that returned array, including on failure. A signature over a fresh random challenge checks RSA, EC and DSA key pairs without exporting private keys. Other algorithms report UNSUPPORTED; provider failures propagate rather than claiming a mismatch.

Each alias maps to entry metadata, certificate reports in chain order, then a chain inspection report. Secret-key entries have only metadata; no secret bytes are read or printed. Incorrect store passwords fail loading; incorrect private-entry passwords produce an entry finding and leave keyPairMatch as NOT_CHECKED.

## Analysis coverage

- Subject, issuer, serial, version, validity dates, remaining whole days and analysis time.
- Public key algorithm/size, certificate and public-key SHA-256 fingerprints.
- Signature algorithm/OID, CA/path-length constraints, numeric key usage flags (X.509 order), EKU OIDs and alternative names.
- Critical/noncritical extension OIDs; raw extension DER OCTET STRING values in Base64, including extensions not decoded by the JDK. Byte-valued alternative names may use the JDK collection string representation; raw DER remains available.
- Self-signature verification; expiry, short RSA key and legacy digest findings.
- JKS and PKCS12 aliases, entry types, creation dates and certificate chains.
- Adjacent issuer/signature checks, validity and CA/keyCertSign findings.
- Optional full JCA PKIX validation against **explicitly supplied** TrustAnchor objects.

Example trust validation (leaf-first ordered list):

```java
new ChainAnalyzer().validate(chain,
    Collections.singleton(new java.security.cert.TrustAnchor(trustedRoot, null)),
    java.time.Instant.now());
```

Signature checks and a self-signed certificate do not establish trust. `inspect` always says NOT_EVALUATED for trust. PKIX validation throws on failure, checks constraints through the provider, and treats supplied anchors as already trusted. An included final anchor is removed before validation. No automatic chain building, AIA download, hostname verification, OS/browser trust-store discovery or OCSP/CRL fetching is performed. Revocation is explicitly disabled. A successful PKIX result is therefore not a complete TLS server validation. Stored trusted-certificate entries are metadata, not automatically used as anchors. These APIs inspect persisted stores; they cannot prove which algorithms were used by an external application to encrypt a particular payload.

Security findings are a small local policy, not a certification/compliance assessment. Extend them for your environment. Reports contain public identity metadata; handle them according to your organization's privacy rules. Store type is explicit; a JDK provider may accept compatible encodings, so the reported type is the requested provider type rather than a forensic format determination.

## Design

Single responsibility separates parsing/inspection (`CertificateAnalyzer`), store loading (`KeyStoreAnalyzer`), possession checks (`KeyPairVerifier`), chain checks (`ChainAnalyzer`) and console interaction. Immutable reports isolate output from mutable JCA objects. The Strategy pattern (`CertificateRule`) permits new policies without editing analysis code. Constructor injection of `Clock` and rule strategies enables deterministic tests; there is no unnecessary framework or singleton.

Analyzer configuration is immutable. Each keystore call loads a separate store and creates operation-local signature/digest objects. Custom rules, password providers and input certificate implementations must themselves be safe for concurrent use. Do not share a caller password array while another thread modifies it.

## Tests

JUnit Jupiter tests generate temporary RSA fixtures with the installed JDK's `keytool` (no real credentials/certificates are committed). They cover JKS/PKCS12, PEM/DER bundles, extension metadata, validity boundaries, custom policies, immutable output, RSA/EC/DSA matching, mismatches, incorrect/null passwords, password clearing, trusted/secret entry types, trust-anchor success, untrusted path rejection and empty chains. Run with a full JDK, not a JRE. Java sources target 8; the tests also use Java 8 APIs.

## Find a particular certificate in a keystore

```sh
java -cp target/utility-1.0-SNAPSHOT.jar com.chetankhandave.utility.certificate.CertificateAnalysisCli find JKS application.jks certificate.pem
```

Use `PKCS12` in place of `JKS` for a PKCS12 store. The CLI accepts exactly one PEM/DER certificate; a bundle is rejected to avoid searching for an unintended certificate. The interactive prompt asks only for the store password.

```java
import com.chetankhandave.utility.certificate.*;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.List;

X509Certificate target = new CertificateAnalyzer()
    .read(Paths.get("certificate.pem")).get(0);
// storePassword comes from your secret source; clear it in your own finally block.
List<CertificateMatch> matches = new KeyStoreCertificateFinder()
    .find(Paths.get("application.jks"), "JKS", storePassword, target);
System.out.println("Certificate found: " + !matches.isEmpty());
for (CertificateMatch match : matches) {
    System.out.println(match.getAlias());
    System.out.println(match.getEntryType());
    System.out.println(match.getCreationTime());
    System.out.println(match.getChainIndex());
    System.out.println(match.getCertificateReport());
}
```

Lookup compares full DER bytes, not subject names, serial numbers or only public keys. It returns all occurrences sorted by alias then chain index, including intermediate/root positions in private key chains. An empty immutable list means absent. Each immutable match contains the alias, entry type, entry creation time (nullable and distinct from certificate issuance), zero-based chain index (`-1` for a standalone trusted certificate), and the existing detailed certificate report. No private key is recovered and no entry password is needed. Secret-key entries are skipped. Presence is independent of expiry or chain trust: finding a certificate does not establish that it is trusted or usable. Loading errors propagate rather than being reported as absence. Caller password arrays remain unchanged; loading uses a cleared temporary copy.

The shared `KeyStoreLoader` centralizes store loading for analysis and lookup. `KeyStoreCertificateFinder` handles searching and delegates public certificate inspection to `CertificateAnalyzer`. Tests include both formats, trusted/leaf/deeper-chain occurrences, duplicate aliases, same-subject nonmatches, absent/empty/secret-only stores, wrong passwords, invalid arguments, immutable results and preserved caller passwords. The deeper-chain fixture is intentionally synthetic: lookup does not validate trust.

## Compare two keystores

```sh
mvn clean test package
java -cp target/utility-1.0-SNAPSHOT.jar com.chetankhandave.utility.certificate.CertificateAnalysisCli compare JKS before.jks JKS after.jks comparison.txt
```

The console prompts separately for both store passwords. The optional final argument writes a UTF-8 report using CREATE_NEW: an existing file is never overwritten. Omit it to print the report. Each store may use `JKS` or `PKCS12` independently. No entry password is requested.

```java
import com.chetankhandave.utility.certificate.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

// Obtain beforePassword/afterPassword as char[] from your secret source.
KeyStoreComparison comparison = new KeyStoreComparator().compare(
    Paths.get("before.jks"), "JKS", beforePassword,
    Paths.get("after.jks"), "JKS", afterPassword);
String report = new TextComparisonReportFormatter().format(comparison);
Files.write(Paths.get("comparison.txt"), report.getBytes(StandardCharsets.UTF_8),
    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
// Caller owns the two password arrays and clears them in a finally block.
```

Comparison is alias based, ordered deterministically. Exact DER encodings determine certificate identity; list order determines chain identity. Reports contain counts, old/new entry and certificate details, field differences, and independent certificate validation findings. A single captured time is used for both stores; analysis timestamps, remaining days and validity status do not create spurious certificate differences. Raw extension encodings are compared via certificate identity and included in field changes. Certificate expiry is a finding, not proof of a change or an indication of trust.

| Status | Meaning |
| --- | --- |
| ADDED / REMOVED | Alias exists in only one store |
| CHANGED | Entry type or certificate/chain contents differ |
| METADATA_CHANGED | Public contents match, but entry creation time differs |
| UNCHANGED | Public contents and compared entry metadata match; underlying keys remain unchecked |
| NOT_COMPARABLE | Secret-key entry with matching metadata; secret material is deliberately not inspected |

For changed certificates, compare `certificate[n].publicKeySha256` in the old/new details to distinguish renewal using the same public key from public key replacement. Chain addition, removal, replacement and reordering are detected; a pure reordering also has a `chainOrder` difference. Identical certificates whose alias sets differ are listed as possible alias renames/copies; duplicate occurrences make that interpretation ambiguous. They remain ADDED/REMOVED under alias comparison. Store provider/type differences are not entry content changes, permitting comparisons across formats. Store password changes and different encrypted file bytes alone do not imply certificate changes.

**Scope:** This compares public certificates/chains and entry metadata. It does not compare private/secret key material, encrypted blobs, store passwords, or file bytes. Even UNCHANGED private-key entries do not prove equal private keys; inspect `keyMaterialComparison=NOT_CHECKED`. Secret-key entries are never called UNCHANGED; metadata changes can still be reported. For optional per-store possession checks use the existing `KeyStoreAnalyzer` with entry password providers; that is separate from comparison. Changed does not imply invalid, and unchanged does not imply valid. PKIX/revocation/hostname validation is not performed by the comparator. Load/parse/password failures throw exceptions, never a misleading empty difference report. Custom output formats can implement the `ComparisonReportFormatter` strategy without changing comparison logic. Reports contain public certificate identity metadata and should be handled accordingly.
