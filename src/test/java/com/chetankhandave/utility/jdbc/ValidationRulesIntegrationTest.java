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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration tests for reusable String/whitelist validation rules using a real
 * H2 in-memory database.
 *
 * <p>These tests intentionally avoid mocking {@link Connection},
 * {@link PreparedStatement}, and {@link ResultSet}. They verify the complete
 * path from {@link SqlParameter} validation through
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
                    + "STATUS VARCHAR(100) NOT NULL)");
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
        insertValue(1, "ACTIVE", ValidationRules.allowedValues(
                "ACTIVE", "INACTIVE", "BLOCKED"));
        assertEquals("ACTIVE", readValue(1));
    }

    /** Verifies an unknown whitelist value is rejected before SQL execution. */
    @Test
    void allowedValuesShouldPreventInsertForUnknownValue() throws SQLException {
        assertThrows(IllegalArgumentException.class,
                () -> insertValue(1, "PENDING",
                        ValidationRules.allowedValues("ACTIVE", "INACTIVE", "BLOCKED")));
        assertFalse(recordExists(1));
    }

    /** Confirms case-sensitive whitelist behavior through a real JDBC flow. */
    @Test
    void allowedValuesShouldRejectDifferentCaseUsingRealJdbc() throws SQLException {
        assertThrows(IllegalArgumentException.class,
                () -> insertValue(1, "active", ValidationRules.allowedValues("ACTIVE")));
        assertFalse(recordExists(1));
    }

    /** Verifies case-insensitive whitelist acceptance and persistence. */
    @Test
    void allowedValuesIgnoreCaseShouldPersistDifferentCaseUsingRealJdbc()
            throws SQLException {
        insertValue(1, "active",
                ValidationRules.allowedValuesIgnoreCase("ACTIVE", "INACTIVE", "BLOCKED"));
        assertEquals("active", readValue(1));
    }

    /** Verifies unknown values remain invalid with case-insensitive matching. */
    @Test
    void allowedValuesIgnoreCaseShouldPreventUnknownValueInsert() throws SQLException {
        assertThrows(IllegalArgumentException.class,
                () -> insertValue(1, "PENDING",
                        ValidationRules.allowedValuesIgnoreCase(
                                "ACTIVE", "INACTIVE", "BLOCKED")));
        assertFalse(recordExists(1));
    }

    /**
     * Verifies matchesPattern through the complete JDBC path using a reference
     * number format that must match the entire value.
     */
    @Test
    void matchesPatternShouldPersistValidFormattedValueUsingRealJdbc() throws SQLException {
        insertValue(1, "REQ-1001", ValidationRules.matchesPattern("REQ-[0-9]{4}"));
        assertEquals("REQ-1001", readValue(1));
    }

    /**
     * Verifies a value outside the configured regex format fails validation and
     * therefore produces no database record.
     */
    @Test
    void matchesPatternShouldPreventInsertForInvalidFormat() throws SQLException {
        assertThrows(IllegalArgumentException.class,
                () -> insertValue(1, "ABC-1001",
                        ValidationRules.matchesPattern("REQ-[0-9]{4}")));
        assertFalse(recordExists(1));
    }

    /** Verifies an ASCII letters/digits value is persisted by the alphanumeric rule. */
    @Test
    void alphanumericShouldPersistValidValueUsingRealJdbc() throws SQLException {
        insertValue(1, "Customer123", ValidationRules.alphanumeric());
        assertEquals("Customer123", readValue(1));
    }

    /**
     * Verifies punctuation/HTML-related characters are rejected by the strict
     * alphanumeric allow-list before the INSERT can execute.
     */
    @Test
    void alphanumericShouldPreventInsertForDisallowedCharacters() throws SQLException {
        assertThrows(IllegalArgumentException.class,
                () -> insertValue(1, "script>alert1", ValidationRules.alphanumeric()));
        assertFalse(recordExists(1));
    }

    /** Verifies ordinary spaces are accepted by alphanumericWithSpace. */
    @Test
    void alphanumericWithSpaceShouldPersistValidValueUsingRealJdbc() throws SQLException {
        insertValue(1, "Customer 123 India", ValidationRules.alphanumericWithSpace());
        assertEquals("Customer 123 India", readValue(1));
    }

    /**
     * Verifies punctuation and HTML-like markup are rejected by the
     * alphanumeric-with-space rule and no row is inserted.
     */
    @Test
    void alphanumericWithSpaceShouldPreventInsertForDisallowedCharacters()
            throws SQLException {
        assertThrows(IllegalArgumentException.class,
                () -> insertValue(1, "<script>alert1</script>",
                        ValidationRules.alphanumericWithSpace()));
        assertFalse(recordExists(1));
    }

    /**
     * Executes an INSERT through the production SqlParameter and binder utility
     * so validation occurs before the PreparedStatement executes.
     */
    private void insertValue(int id,
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

    /** Reads the stored value back from H2 after successful validation/execution. */
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
