package com.chetankhandave.utility.jdbc;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration tests for reusable validation rules using a real H2 in-memory
 * database.
 *
 * <p>These tests intentionally avoid mocking JDBC objects. They verify the
 * complete path from {@link SqlParameter} validation through
 * {@link PreparedStatementBinder} binding and real SQL execution.</p>
 */
class ValidationRulesIntegrationTest {

    private Connection connection;

    /** Creates a fresh table before every test for isolated database state. */
    @BeforeEach
    void setUp() throws SQLException {
        connection = DriverManager.getConnection(
                "jdbc:h2:mem:allowed_values_validation;DB_CLOSE_DELAY=-1");

        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP TABLE IF EXISTS ACCOUNT_STATUS");
            statement.execute("CREATE TABLE ACCOUNT_STATUS ("
                    + "ID INT PRIMARY KEY, "
                    + "STATUS VARCHAR(100))");
        }
    }

    /** Closes the real JDBC connection after each integration-test scenario. */
    @AfterEach
    void tearDown() throws SQLException {
        if (connection != null) {
            connection.close();
        }
    }

    /** Verifies a configured case-sensitive whitelist value is persisted. */
    @Test
    void allowedValuesShouldPersistConfiguredValueUsingRealJdbc() throws SQLException {
        insertRequiredValue(1, "ACTIVE", ValidationRules.allowedValues(
                "ACTIVE", "INACTIVE", "BLOCKED"));
        assertEquals("ACTIVE", readValue(1));
    }

    /** Verifies an unknown whitelist value is rejected before SQL execution. */
    @Test
    void allowedValuesShouldPreventInsertForUnknownValue() throws SQLException {
        assertThrows(IllegalArgumentException.class,
                () -> insertRequiredValue(1, "PENDING",
                        ValidationRules.allowedValues("ACTIVE", "INACTIVE", "BLOCKED")));
        assertFalse(recordExists(1));
    }

    /** Confirms case-sensitive whitelist behavior through a real JDBC flow. */
    @Test
    void allowedValuesShouldRejectDifferentCaseUsingRealJdbc() throws SQLException {
        assertThrows(IllegalArgumentException.class,
                () -> insertRequiredValue(1, "active", ValidationRules.allowedValues("ACTIVE")));
        assertFalse(recordExists(1));
    }

    /** Verifies case-insensitive whitelist acceptance and persistence. */
    @Test
    void allowedValuesIgnoreCaseShouldPersistDifferentCaseUsingRealJdbc()
            throws SQLException {
        insertRequiredValue(1, "active",
                ValidationRules.allowedValuesIgnoreCase("ACTIVE", "INACTIVE", "BLOCKED"));
        assertEquals("active", readValue(1));
    }

    /** Verifies unknown values remain invalid with case-insensitive matching. */
    @Test
    void allowedValuesIgnoreCaseShouldPreventUnknownValueInsert() throws SQLException {
        assertThrows(IllegalArgumentException.class,
                () -> insertRequiredValue(1, "PENDING",
                        ValidationRules.allowedValuesIgnoreCase(
                                "ACTIVE", "INACTIVE", "BLOCKED")));
        assertFalse(recordExists(1));
    }

    /** Verifies matchesPattern through the complete JDBC path. */
    @Test
    void matchesPatternShouldPersistValidFormattedValueUsingRealJdbc() throws SQLException {
        insertRequiredValue(1, "REQ-1001", ValidationRules.matchesPattern("REQ-[0-9]{4}"));
        assertEquals("REQ-1001", readValue(1));
    }

    /** Verifies invalid regex-format input produces no database record. */
    @Test
    void matchesPatternShouldPreventInsertForInvalidFormat() throws SQLException {
        assertThrows(IllegalArgumentException.class,
                () -> insertRequiredValue(1, "ABC-1001",
                        ValidationRules.matchesPattern("REQ-[0-9]{4}")));
        assertFalse(recordExists(1));
    }

    /** Verifies an ASCII letters/digits value is persisted by alphanumeric. */
    @Test
    void alphanumericShouldPersistValidValueUsingRealJdbc() throws SQLException {
        insertRequiredValue(1, "Customer123", ValidationRules.alphanumeric());
        assertEquals("Customer123", readValue(1));
    }

    /** Verifies disallowed characters are rejected before the INSERT executes. */
    @Test
    void alphanumericShouldPreventInsertForDisallowedCharacters() throws SQLException {
        assertThrows(IllegalArgumentException.class,
                () -> insertRequiredValue(1, "script>alert1", ValidationRules.alphanumeric()));
        assertFalse(recordExists(1));
    }

    /** Verifies ordinary spaces are accepted by alphanumericWithSpace. */
    @Test
    void alphanumericWithSpaceShouldPersistValidValueUsingRealJdbc() throws SQLException {
        insertRequiredValue(1, "Customer 123 India", ValidationRules.alphanumericWithSpace());
        assertEquals("Customer 123 India", readValue(1));
    }

    /** Verifies HTML-like markup is rejected and no row is inserted. */
    @Test
    void alphanumericWithSpaceShouldPreventInsertForDisallowedCharacters()
            throws SQLException {
        assertThrows(IllegalArgumentException.class,
                () -> insertRequiredValue(1, "<script>alert1</script>",
                        ValidationRules.alphanumericWithSpace()));
        assertFalse(recordExists(1));
    }

    /**
     * Verifies the JDBC nullable path remains compatible with null-safe rules.
     * SqlParameter.nullable intentionally skips value rules for null and binds
     * SQL NULL, which must be persisted successfully by the real database.
     */
    @Test
    void nullableParameterShouldPersistSqlNullWithNullSafeRules() throws SQLException {
        insertNullableValue(1, null,
                ValidationRules.notBlank(),
                ValidationRules.maxLength(20),
                ValidationRules.alphanumeric());

        assertTrue(recordExists(1));
        assertNull(readValue(1));
    }

    /**
     * Verifies required null handling remains owned by SqlParameter and fails
     * cleanly before SQL execution, independent of the attached null-safe rule.
     */
    @Test
    void requiredNullShouldFailBeforeDatabaseInsert() throws SQLException {
        assertThrows(IllegalArgumentException.class,
                () -> insertRequiredValue(1, null, ValidationRules.alphanumeric()));
        assertFalse(recordExists(1));
    }

    /** Executes an INSERT using a required String parameter. */
    private void insertRequiredValue(int id,
                                     String value,
                                     ValidationRule<String> rule) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO ACCOUNT_STATUS (ID, STATUS) VALUES (?, ?)")) {
            PreparedStatementBinder.bind(
                    statement,
                    SqlParameter.required("id", id, Types.INTEGER,
                            ValidationRules.positiveInteger()),
                    SqlParameter.required("status", value, Types.VARCHAR,
                            ValidationRules.notBlank(), rule));
            statement.executeUpdate();
        }
    }

    /** Executes an INSERT using a nullable String parameter and multiple rules. */
    @SafeVarargs
    private final void insertNullableValue(int id,
                                           String value,
                                           ValidationRule<String>... rules)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO ACCOUNT_STATUS (ID, STATUS) VALUES (?, ?)")) {
            PreparedStatementBinder.bind(
                    statement,
                    SqlParameter.required("id", id, Types.INTEGER,
                            ValidationRules.positiveInteger()),
                    SqlParameter.nullable("status", value, Types.VARCHAR, rules));
            statement.executeUpdate();
        }
    }

    /** Reads the stored value back from H2 after successful execution. */
    private String readValue(int id) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT STATUS FROM ACCOUNT_STATUS WHERE ID = ?")) {
            statement.setInt(1, id);
            try (ResultSet resultSet = statement.executeQuery()) {
                assertTrue(resultSet.next());
                return resultSet.getString("STATUS");
            }
        }
    }

    /** Checks whether validation failure prevented a row from being inserted. */
    private boolean recordExists(int id) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT COUNT(*) FROM ACCOUNT_STATUS WHERE ID = ?")) {
            statement.setInt(1, id);
            try (ResultSet resultSet = statement.executeQuery()) {
                assertTrue(resultSet.next());
                return resultSet.getInt(1) > 0;
            }
        }
    }
}
