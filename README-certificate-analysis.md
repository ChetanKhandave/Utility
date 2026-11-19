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
