package com.chetankhandave.utility.certificate;

import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import com.google.gson.Strictness;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.w3c.dom.*;
import org.xml.sax.InputSource;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

/** Independent parsers check report semantics and escaping, not just string templates. */
class ComparisonReportFormatterTest {
    private static AnalysisReport report(String key,String value,String finding) {
        Map<String,String> details=new LinkedHashMap<>(); details.put(key,value);
        return new AnalysisReport(details,finding==null?Collections.emptyList():Arrays.asList(finding));
    }
    private static KeyStoreComparison sample(String text) {
        List<AnalysisReport> before=Arrays.asList(report("entryType","PRIVATE_KEY",null),
            report("subject",text,"Local finding: "+text),report("issuer",text,null));
        List<AnalysisReport> after=Arrays.asList(report("entryType","PRIVATE_KEY",null),report("subject",text,null));
        KeyStoreComparison.Entry entry=new KeyStoreComparison.Entry(text,KeyStoreComparison.Status.CHANGED,
            Arrays.asList(new KeyStoreComparison.Difference(text,null,text),new KeyStoreComparison.Difference("removed",text,null)),before,after);
        return new KeyStoreComparison(Arrays.asList(entry),Arrays.asList(text));
    }
    private static JsonObject json(KeyStoreComparison comparison) throws Exception {
        return parseJson(new JsonComparisonReportFormatter().format(comparison));
    }
    private static JsonObject parseJson(String text) throws Exception {
        JsonReader reader=new JsonReader(new StringReader(text));reader.setStrictness(Strictness.STRICT);
        JsonObject root=JsonParser.parseReader(reader).getAsJsonObject();
        assertEquals(com.google.gson.stream.JsonToken.END_DOCUMENT,reader.peek()); return root;
    }
    private static Document html(KeyStoreComparison comparison) throws Exception {
        DocumentBuilderFactory factory=DocumentBuilderFactory.newInstance();
        factory.setFeature("http://xml.org/sax/features/external-general-entities",false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities",false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd",false);
        return factory.newDocumentBuilder().parse(new InputSource(new StringReader(new HtmlComparisonReportFormatter().format(comparison))));
    }
    private static KeyStoreComparison empty() { return new KeyStoreComparison(Collections.emptyList(),Collections.emptyList()); }
    @Test void emptyJsonHasVersionNumericCountsAndExplicitScope() throws Exception {
        JsonObject root=json(empty());assertEquals("1.0",root.get("schemaVersion").getAsString());
        assertEquals(6,root.getAsJsonObject("summary").size());
        for(JsonElement count:root.getAsJsonObject("summary").asMap().values()) {
            assertTrue(count.getAsJsonPrimitive().isNumber());assertEquals(0,count.getAsInt());
        }
        assertTrue(root.getAsJsonArray("entries").isEmpty()); assertTrue(root.getAsJsonArray("certificateRelocations").isEmpty());
        assertEquals("NOT_CHECKED",root.getAsJsonObject("scope").get("privateKeyMaterial").getAsString());
        assertEquals("NOT_CHECKED",root.getAsJsonObject("scope").get("secretKeyMaterial").getAsString());
        assertEquals("NOT_PERFORMED",root.getAsJsonObject("scope").get("trustValidation").getAsString());
    }
    @ParameterizedTest @EnumSource(KeyStoreComparison.Status.class)
    void allStatusesRemainConsistentAcrossFormats(KeyStoreComparison.Status status) throws Exception {
        KeyStoreComparison comparison=new KeyStoreComparison(Arrays.asList(new KeyStoreComparison.Entry("alias",status,
            Collections.emptyList(),Collections.emptyList(),Collections.emptyList())),Collections.emptyList());
        JsonObject root=json(comparison);assertEquals(1,root.getAsJsonObject("summary").get(status.name()).getAsInt());
        assertEquals(status.name(),root.getAsJsonArray("entries").get(0).getAsJsonObject().get("status").getAsString());
        Document document=html(comparison);assertEquals(status.name(),document.getElementsByTagName("article").item(0).getAttributes().getNamedItem("class").getNodeValue());
    }
    @Test void jsonPreservesNullsAndCompleteSnapshots() throws Exception {
        JsonObject entry=json(sample("data")).getAsJsonArray("entries").get(0).getAsJsonObject();
        assertTrue(entry.getAsJsonArray("differences").get(0).getAsJsonObject().get("before").isJsonNull());
        assertTrue(entry.getAsJsonArray("differences").get(1).getAsJsonObject().get("after").isJsonNull());
        JsonObject before=entry.getAsJsonObject("before"); assertEquals("PRIVATE_KEY",before.getAsJsonObject("entry").getAsJsonObject("details").get("entryType").getAsString());
        assertEquals(2,before.getAsJsonArray("certificates").size());
        assertEquals(1,before.getAsJsonArray("certificates").get(1).getAsJsonObject().get("chainIndex").getAsInt());
        assertEquals("Local finding: data",before.getAsJsonArray("certificates").get(0).getAsJsonObject().getAsJsonArray("findings").get(0).getAsString());
        assertEquals(1,entry.getAsJsonObject("after").getAsJsonArray("certificates").size());
    }
    @Test void absentEntryAndEmptyStringAreDistinctFromNull() throws Exception {
        KeyStoreComparison comparison=new KeyStoreComparison(Arrays.asList(new KeyStoreComparison.Entry("",KeyStoreComparison.Status.ADDED,
            Arrays.asList(new KeyStoreComparison.Difference("",null,"")),Collections.emptyList(),Arrays.asList(report("nullable",null,null)))),Collections.emptyList());
        JsonObject entry=json(comparison).getAsJsonArray("entries").get(0).getAsJsonObject();
        assertTrue(entry.get("before").isJsonNull()); assertEquals("",entry.get("alias").getAsString());
        assertEquals("",entry.getAsJsonArray("differences").get(0).getAsJsonObject().get("after").getAsString());
        assertTrue(entry.getAsJsonObject("after").getAsJsonObject("entry").getAsJsonObject("details").get("nullable").isJsonNull());
        assertTrue(html(comparison).getDocumentElement().getTextContent().contains("Entry absent"));
    }
    @Test void jsonRoundTripsQuotesSlashesAndEveryAsciiControl() throws Exception {
        StringBuilder text=new StringBuilder("\"\\/\n\r\t");for(char c=0;c<32;c++)text.append(c);
        String value=text.toString();
        JsonObject root=json(sample(value));
        assertEquals(value,root.getAsJsonArray("entries").get(0).getAsJsonObject().get("alias").getAsString());
        assertEquals(value,root.getAsJsonArray("certificateRelocations").get(0).getAsString());
        assertEquals(value,root.getAsJsonArray("entries").get(0).getAsJsonObject().getAsJsonArray("differences").get(0).getAsJsonObject().get("field").getAsString());
    }
    @Test void unicodeAndSupplementaryCharactersRoundTrip() throws Exception {
        String value="मराठी 日本語 café \uD83D\uDD10 \u2028\u2029";
        assertEquals(value,json(sample(value)).getAsJsonArray("entries").get(0).getAsJsonObject().get("alias").getAsString());
        assertTrue(html(sample(value)).getDocumentElement().getTextContent().contains(value));
    }
    @Test void unpairedSurrogatesAreEscaped() throws Exception {
        String value="bad\uD800x\uDC00";
        assertEquals(value,json(sample(value)).getAsJsonArray("entries").get(0).getAsJsonObject().get("alias").getAsString());
        String content=html(sample(value)).getDocumentElement().getTextContent();
        assertTrue(content.contains("bad\\ud800x\\udc00"));
    }
    @Test void htmlEscapesEveryUntrustedTextLocation() throws Exception {
        String payload="</td><script>alert('x')</script><img src=x onerror=alert(1)> & \"quoted\"";
        Document document=html(sample(payload));
        assertEquals(0,document.getElementsByTagName("script").getLength());
        assertEquals(0,document.getElementsByTagName("img").getLength());
        assertTrue(document.getElementsByTagName("h2").item(0).getTextContent().endsWith(payload));
        assertTrue(document.getDocumentElement().getTextContent().contains("Local finding: "+payload));
        NodeList elements=document.getElementsByTagName("*");
        for(int i=0;i<elements.getLength();i++) {
            NamedNodeMap attributes=elements.item(i).getAttributes();
            for(int j=0;j<attributes.getLength();j++)assertFalse(attributes.item(j).getNodeName().startsWith("on"));
        }
    }
    @Test void htmlControlsAndNoncharactersRemainParseable() throws Exception {
        StringBuilder value=new StringBuilder();for(char c=0;c<32;c++)value.append(c);value.append('\ufffe').append('\uffff');
        assertTrue(html(sample(value.toString())).getDocumentElement().getTextContent().contains("\\u0000"));
    }
    @Test void htmlHasOfflinePolicyAccessibleTablesAndCssOnlyFilter() throws Exception {
        Document document=html(sample("alias"));
        assertEquals("html",document.getDocumentElement().getNodeName());
        assertEquals(0,document.getElementsByTagName("script").getLength());
        assertEquals(0,document.getElementsByTagName("link").getLength());
        assertEquals("changes-only",document.getElementsByTagName("input").item(0).getAttributes().getNamedItem("id").getNodeValue());
        assertTrue(document.getElementsByTagName("style").item(0).getTextContent().contains("#changes-only:checked ~ main article.UNCHANGED"));
        assertTrue(document.getElementsByTagName("details").getLength()>0);
        assertTrue(document.getElementsByTagName("th").item(0).getAttributes().getNamedItem("scope")!=null);
        assertTrue(new HtmlComparisonReportFormatter().format(sample("alias")).contains("default-src 'none'"));
    }
    @Test void emptyHtmlExplainsEmptyResult() throws Exception {
        assertTrue(html(empty()).getDocumentElement().getTextContent().contains("No entries in either keystore"));
    }
    @Test void largeFieldsAreNotTruncated() throws Exception {
        char[] chars=new char[100000];Arrays.fill(chars,'a');String value=new String(chars);
        assertEquals(value,json(sample(value)).getAsJsonArray("entries").get(0).getAsJsonObject().get("alias").getAsString());
        assertTrue(html(sample(value)).getElementsByTagName("h2").item(0).getTextContent().endsWith(value));
    }
    @Test void nullComparisonRejectedByNewFormatters() {
        assertThrows(NullPointerException.class,()->new JsonComparisonReportFormatter().format(null));
        assertThrows(NullPointerException.class,()->new HtmlComparisonReportFormatter().format(null));
    }
    @Test void formatSelectionIsCaseInsensitiveAndRejectsUnknown() {
        assertEquals(ComparisonReportFormat.JSON,ComparisonReportFormat.parse("json"));
        assertEquals(ComparisonReportFormat.HTML,ComparisonReportFormat.parse("HtMl"));
        assertInstanceOf(TextComparisonReportFormatter.class,ComparisonReportFormat.TEXT.formatter());
        assertInstanceOf(JsonComparisonReportFormatter.class,ComparisonReportFormat.JSON.formatter());
        assertInstanceOf(HtmlComparisonReportFormatter.class,ComparisonReportFormat.HTML.formatter());
        assertThrows(IllegalArgumentException.class,()->ComparisonReportFormat.parse("xml"));
        assertThrows(IllegalArgumentException.class,()->ComparisonReportFormat.parse(""));
        assertThrows(NullPointerException.class,()->ComparisonReportFormat.parse(null));
    }
    @Test void cliRejectsInvalidFormatBeforePromptingForSecrets() {
        assertThrows(IllegalArgumentException.class,()->CertificateAnalysisCli.main(new String[]{"compare","JKS","old","JKS","new","out","--format","xml"}));
        assertThrows(IllegalArgumentException.class,()->CertificateAnalysisCli.main(new String[]{"compare","JKS","old","JKS","new","out","--wrong","json"}));
    }
    @Test void formattersAreDeterministicAndSafeToShareBetweenThreads() throws Exception {
        KeyStoreComparison comparison=sample("concurrent");
        ExecutorService pool=Executors.newFixedThreadPool(4);
        try {
            for(ComparisonReportFormatter formatter:Arrays.asList(new JsonComparisonReportFormatter(),new HtmlComparisonReportFormatter())) {
                String expected=formatter.format(comparison);List<Callable<String>> tasks=new ArrayList<>();
                for(int i=0;i<20;i++)tasks.add(()->formatter.format(comparison));
                for(Future<String> result:pool.invokeAll(tasks))assertEquals(expected,result.get());
            }
        } finally { pool.shutdownNow(); }
    }

    @org.junit.jupiter.api.io.TempDir java.nio.file.Path outputDirectory;
    @Test void writesUtf8JsonAndHtmlWithoutRuntimeDependencies() throws Exception {
        KeyStoreComparison comparison=sample("मराठी 🔐");
        for(ComparisonReportFormat format:Arrays.asList(ComparisonReportFormat.JSON,ComparisonReportFormat.HTML)) {
            java.nio.file.Path path=outputDirectory.resolve(format.name());
            new ComparisonReportWriter().write(path,comparison,format.formatter());
            String content=new String(java.nio.file.Files.readAllBytes(path),java.nio.charset.StandardCharsets.UTF_8);
            assertEquals(format.formatter().format(comparison),content);
            if(format==ComparisonReportFormat.JSON) assertEquals("मराठी 🔐",parseJson(content).getAsJsonArray("entries").get(0).getAsJsonObject().get("alias").getAsString());
        }
    }
    @Test void writerNeverOverwritesExistingFile() throws Exception {
        java.nio.file.Path path=outputDirectory.resolve("existing.jks");
        byte[] original=new byte[]{1,2,3};java.nio.file.Files.write(path,original);
        assertThrows(java.nio.file.FileAlreadyExistsException.class,()->new ComparisonReportWriter().write(path,empty(),new JsonComparisonReportFormatter()));
        assertArrayEquals(original,java.nio.file.Files.readAllBytes(path));
    }
    @Test void writerPropagatesIoFailuresAndDoesNotCreateFileOnFormatterFailure() {
        ComparisonReportWriter writer=new ComparisonReportWriter();
        assertThrows(java.io.IOException.class,()->writer.write(outputDirectory.resolve("missing/report.json"),empty(),new JsonComparisonReportFormatter()));
        java.nio.file.Path output=outputDirectory.resolve("not-created");
        assertThrows(IllegalStateException.class,()->writer.write(output,empty(),comparison->{throw new IllegalStateException("failed");}));
        assertFalse(java.nio.file.Files.exists(output));
        assertThrows(NullPointerException.class,()->writer.write(null,empty(),new JsonComparisonReportFormatter()));
        assertThrows(NullPointerException.class,()->writer.write(output,null,new JsonComparisonReportFormatter()));
        assertThrows(NullPointerException.class,()->writer.write(output,empty(),null));
    }
}
