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

## JSON and HTML comparison reports

The existing TEXT command remains compatible. Explicit format selection follows the output path:

```sh
java -cp target/utility-1.0-SNAPSHOT.jar com.chetankhandave.utility.certificate.CertificateAnalysisCli compare JKS before.jks JKS after.jks comparison.json --format JSON
java -cp target/utility-1.0-SNAPSHOT.jar com.chetankhandave.utility.certificate.CertificateAnalysisCli compare JKS before.jks JKS after.jks comparison.html --format HTML
```

Format names are case insensitive. TEXT is the default; extensions do not select the format. Both commands prompt for store passwords. Output files must not already exist. Reports are written as UTF-8. Open the HTML file directly in a browser: no server, internet connection, JavaScript, or external assets are required. Its summary, coloured status labels, side-by-side field changes, expandable before/after details and CSS-only **Hide unchanged entries** checkbox support manual review. The filter keeps NOT_COMPARABLE entries visible. Collapsed detail sections should be expanded before printing when full details are needed.

Use a single comparison result to generate both formats in Java:

```java
KeyStoreComparison comparison = new KeyStoreComparator().compare(
    Paths.get("before.jks"), "JKS", beforePassword,
    Paths.get("after.jks"), "JKS", afterPassword);
ComparisonReportWriter writer = new ComparisonReportWriter();
writer.write(Paths.get("comparison.json"), comparison, new JsonComparisonReportFormatter());
writer.write(Paths.get("comparison.html"), comparison, new HtmlComparisonReportFormatter());
```

Both formatters implement the existing `ComparisonReportFormatter` Strategy interface. The small `ComparisonReportFormat` factory selects a strategy for the CLI. Formatting does not reload stores or modify comparison data; `ComparisonReportWriter` handles encoding and file creation separately. Production code still has no external dependencies. Gson is test-only and independently parses JSON output in strict mode. Formatters have no mutable instance state and can be shared across threads with immutable comparison results.

### JSON schema version 1.0

- `schemaVersion`: string `1.0`.
- `summary`: numeric counts keyed by the existing uppercase status names, including zero counts.
- `scope`: `privateKeyMaterial=NOT_CHECKED`, `secretKeyMaterial=NOT_CHECKED`, `trustValidation=NOT_PERFORMED`.
- `entries`: ordered array of objects containing `alias`, `status`, `differences`, `before`, and `after`.
- Each difference has `field`, `before`, and `after`. Missing values are JSON null, not the string `"null"` or an empty string.
- Each present snapshot contains `entry` (metadata report) and `certificates` (ordered reports with zero-based `chainIndex`). Reports contain a `details` object and a `findings` array. Absent snapshots are JSON null.
- `certificateRelocations`: observations about identical certificates whose alias sets changed, not proof of a rename.

Metadata values retain their existing string/null representation; only counts and chain indices are JSON numbers. Raw key bytes and passwords are never added. JSON preserves Unicode, quotes, backslashes and controls via standard escaping. It is a standalone data format, not a script fragment for embedding in a webpage. HTML escapes all report-derived text and uses fixed status names in CSS classes. Unsupported HTML control characters and unpaired surrogates are displayed as visible `\\uXXXX` escapes; valid supplementary characters are preserved.

### Formatter verification

The JUnit suite covers empty reports, all six statuses, missing snapshots and null versus empty values, chain indices and unequal chain lengths, complete findings/details, relocation observations, JSON parsing with an independent strict parser, quotes/backslashes/all ASCII controls, international text and supplementary characters, unpaired surrogates, HTML/script injection in every text category, HTML document parsing, offline policy and filter markup, large fields, null arguments, unknown formats, deterministic concurrent rendering, UTF-8 files, I/O failures, preservation of existing files and formatter failure before file creation. Existing certificate, lookup and comparison tests remain part of the suite. Tests cover the specified boundaries; they are not a claim that every possible input has been exhaustively tested.

## Deployment validation: expected changes, renewal and truststore

All three independent validators are now available together. Start with `examples/deployment-validation.properties` and edit the aliases and requirements for your application.

```sh
java -cp target/utility-1.0-SNAPSHOT.jar com.chetankhandave.utility.certificate.CertificateAnalysisCli validate JKS before.jks JKS after.jks PKCS12 truststore.p12 examples/deployment-validation.properties validation.html --format HTML
```

Use `--format JSON` or `--format TEXT` and a new output filename for other reports. Both stores and the truststore independently accept JKS/PKCS12. The command prompts for three store passwords; entry passwords are unnecessary. No keystore is modified. UTF-8 policy files are loaded through a Reader; unknown properties, malformed booleans, invalid statuses and contradictory change requirements are rejected before prompting. Reports use CREATE_NEW and cannot overwrite existing files. Exit code 0 means PASS, 2 means a completed report with FAIL/NOT_CHECKED/ERROR, and uncaught configuration/input/output failures produce the JVM's nonzero exit. All password arrays are cleared before an explicit exit.

### Java API

```java
import com.chetankhandave.utility.certificate.*;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Properties;

Properties properties = new Properties();
try (Reader reader = Files.newBufferedReader(
        Paths.get("deployment-validation.properties"), StandardCharsets.UTF_8)) {
    properties.load(reader);
}
DeploymentValidationPolicy policy = DeploymentValidationPolicy.fromProperties(properties);
// Retrieve beforePassword, afterPassword and trustPassword as char[] from your secret source.
// Caller owns and clears these arrays in a finally block.
DeploymentValidationReport result = new DeploymentValidationService().validate(
    Paths.get("before.jks"), "JKS", beforePassword,
    Paths.get("after.jks"), "JKS", afterPassword,
    Paths.get("truststore.p12"), "PKCS12", trustPassword, policy);
String json = new DeploymentValidationReportFormatter().format(result, ComparisonReportFormat.JSON);
String html = new DeploymentValidationReportFormatter().format(result, ComparisonReportFormat.HTML);
System.out.println(result.getStatus());
```

Each keystore is loaded once for this workflow and all analysis uses one captured validation instant (inject a `Clock` for reproducibility). This provides a consistent in-memory snapshot after loading, not an atomic snapshot across separately changing files. Keep input files stable while they are loaded. A comparison or main-store load failure stops preparation with an exception; truststore loading is deferred to its validator so that its failure does not hide the other results.

### Expected-change rules

- Changes are **denied by default**. `allowChange.<alias>` accepts a comma-separated subset of `ADDED`, `REMOVED`, `CHANGED`, `METADATA_CHANGED` for an exact enumerated alias. For example `allowChange.old-ca=REMOVED` permits only that alias's removal.
- `requireChange.<alias>` requires an actual observed status from the listed set; these statuses must also appear in the alias's allowlist. A permission alone does not force a change.
- `requiredAliases` requires the aliases to exist in the new store. An approved removal does not satisfy this requirement.
- CHANGED is the existing comparator's entry-content status, including entry-type and chain differences; it is not a fine-grained field allowlist. Use renewal requirements to constrain the target replacement certificate further.
- Metadata-only changes require explicit permission. A same-alias secret entry reported NOT_COMPARABLE yields required NOT_CHECKED; this tool cannot prove secret material stayed unchanged. A private-key entry marked unchanged refers to public certificates/metadata only, never proof of unchanged private keys.

### Renewal rules

The target is the new store's `target.alias` certificate (leaf for a key entry). The old alias supplies the baseline. The new certificate must be valid at the captured instant and meet the inclusive minimum remaining duration; expiry must advance by default. Subject preservation, end-entity requirement, exact DNS SANs, explicit KU bits, explicit EKU OIDs and public-key rotation can be configured. `RenewalPolicy.builder()` also supports direct programmatic construction.

DNS checks require explicit SAN values after IDN/case/trailing-dot normalization; they do not use CN fallback, wildcard expansion, or IP-address SAN matching. These are certificate-content requirements, not a complete TLS hostname-verification implementation. Required KU/EKU extensions must exist and explicitly contain the requested bits/OIDs; absent extensions and anyExtendedKeyUsage alone do not satisfy this conservative policy. Public key policy compares encoded public keys, not private keys. A missing new certificate fails. A missing old certificate produces required NOT_CHECKED when expiry/subject/key comparison needs it; for a first issuance, disable the baseline-dependent requirements explicitly. The old certificate need not still be valid to assess its renewal.

### Truststore rules and revocation scope

Only explicitly selected `trust.anchorAliases` **trusted-certificate entries** become anchors. A private-key alias, missing alias or wrong truststore password becomes a trust execution ERROR when run through the coordinator. Unselected certificates in the truststore/new store may supply intermediates but are not promoted to anchors. PKIX builds a path from an unordered local candidate collection, enforcing chain signatures, intermediate CA/key usage/path-length constraints, validity and provider algorithm constraints. Local policy additionally requires every selected anchor to be a valid CA at the captured instant with keyCertSign permitted if its KU extension is present. Invalid selected anchors fail even if another selected anchor can build a path.

`trust.revocation=DISABLED` explicitly disables provider revocation checks and emits visible optional NOT_CHECKED; other successful checks may still yield PASS under that declared scope. `REQUIRED` emits **required NOT_CHECKED**, preventing PASS because OCSP/CRL verification is not implemented. No unchecked revocation is presented as successful. This is not a full TLS handshake, hostname check or universal statement of certificate trust. Runtime PKIX provider settings may affect path building, including AIA issuer fetching if the runtime has enabled it; the utility does not alter global security settings or provide an HTTP fetcher. For offline operation use local chains and a provider/runtime configuration with remote fetching disabled.

The implementation uses the standard JCA [PKIXBuilderParameters](https://docs.oracle.com/javase/8/docs/api/java/security/cert/PKIXBuilderParameters.html) and [PKIXParameters](https://docs.oracle.com/javase/8/docs/api/java/security/cert/PKIXParameters.html) APIs; revocation behaviour is explicitly configured rather than relying on provider defaults.

### Results and combined reports

`ValidationCheck` is the Strategy interface; the coordinator runs independent checks and catches their execution exceptions without serializing exception messages that could expose secrets. Policies/results are immutable defensive copies, renewal uses a Builder, and the service is a facade over the comparison and validator components. Custom checks can join the coordinator without changing existing validators.

- Rule results contain stable rule IDs, status, message and `required`.
- ERROR takes precedence over FAIL, then required NOT_CHECKED, then PASS. Optional unchecked rules remain visible but do not block an otherwise successful check. An empty/all-unchecked result never passes.
- Overall status aggregates every validator. One failed requirement or required unchecked validator prevents overall PASS.
- Combined JSON is a versioned envelope with `schemaVersion`, the existing `comparison` document, and `validation` containing `status` and `checks`. The required flag is a JSON boolean. Existing comparison-only JSON schema remains unchanged.
- Combined HTML retains the comparison and appends separately labelled rule outcomes. All validation-derived text is escaped. Text reports also escape control characters.

### Validation tests and platform limits

Every new test and fixture helper has Javadoc describing its scenario. Tests include all approved change categories, denied aliases/statuses, mandatory-change absence, removed required aliases, immutable policy inputs, renewal validity endpoints/minimum-duration boundary, exact DNS/IDN handling, absent KU/EKU, key rotation/retention, missing baseline, real signed root/intermediate/leaf PKIX path building, missing issuers, unapproved anchors, invalid signatures, expired/future certificates, CA/key-usage/path-length constraints, explicit anchor selection, required revocation, independent failures, both store formats, password preservation, aggregation precedence, concurrent renewal checks, combined report escaping and CLI argument rejection. Existing tests remain included. Test cases cover these identified boundaries, not every possible certificate/provider combination.

Bouncy Castle is a **test-only** dependency used to generate deterministic signed certificate fixtures; production still uses only JCA APIs. Validation was compiled for Java 8 source compatibility and executed on Java 21, not on an actual Java 8 runtime. Algorithm/provider support can differ across installed JDK versions; run `mvn clean test` on the intended JDK before deployment.
