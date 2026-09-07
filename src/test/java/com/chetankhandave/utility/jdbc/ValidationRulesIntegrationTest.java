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
 * Integration tests for allowed-values validation using a real H2 database.
 *
 * <p>These tests intentionally avoid mocking {@link Connection},
 * {@link PreparedStatement}, and {@link ResultSet}. They verify the complete
 * path from {@link SqlParameter} validation through
 * {@link PreparedStatementBinder} binding and real SQL execution.</p>
 */
class ValidationRulesIntegrationTest {

    private Connection connection;

    /**
     * Creates a fresh in-memory table before every test so each scenario has an
     * isolated and predictable database state.
     */
    @BeforeEach
    void setUp() throws SQLException {
        connection = DriverManager.getConnection(
                "jdbc:h2:mem:allowed_values_validation;DB_CLOSE_DELAY=-1");

        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP TABLE IF EXISTS ACCOUNT_STATUS");
            statement.execute("CREATE TABLE ACCOUNT_STATUS ("
                    + "ID INT PRIMARY KEY, "
                    + "STATUS VARCHAR(20) NOT NULL)");
        }
    }

    /**
     * Closes the real JDBC connection after every integration-test scenario to
     * prevent resource leakage.
     */
    @AfterEach
    void tearDown() throws SQLException {
        if (connection != null) {
            connection.close();
        }
    }

    /**
     * Verifies that an exact member of a case-sensitive allowed-values whitelist
     * is successfully bound to a real PreparedStatement and persisted by H2.
     */
    @Test
    void allowedValuesShouldPersistConfiguredValueUsingRealJdbc() throws SQLException {
        insertStatus(1, "ACTIVE", ValidationRules.allowedValues(
                "ACTIVE", "INACTIVE", "BLOCKED"));

        assertEquals("ACTIVE", readStatus(1));
    }

    /**
     * Verifies that a value outside the whitelist is rejected before SQL
     * execution. Because binding fails first, no row must be inserted.
     */
    @Test
    void allowedValuesShouldPreventInsertForUnknownValue() throws SQLException {
        assertThrows(
                IllegalArgumentException.class,
                () -> insertStatus(
                        1,
                        "PENDING",
                        ValidationRules.allowedValues(
                                "ACTIVE", "INACTIVE", "BLOCKED")));

        assertFalse(recordExists(1));
    }

    /**
     * Confirms that the generic allowed-values rule remains case-sensitive in a
     * real JDBC flow. Lowercase input must be rejected when only uppercase text
     * is configured.
     */
    @Test
    void allowedValuesShouldRejectDifferentCaseUsingRealJdbc() throws SQLException {
        assertThrows(
                IllegalArgumentException.class,
                () -> insertStatus(
                        1,
                        "active",
                        ValidationRules.allowedValues("ACTIVE")));

        assertFalse(recordExists(1));
    }

    /**
     * Verifies the case-insensitive rule through the complete JDBC path. The
     * lowercase input is valid against the uppercase whitelist and is persisted
     * exactly as supplied by the caller.
     */
    @Test
    void allowedValuesIgnoreCaseShouldPersistDifferentCaseUsingRealJdbc()
            throws SQLException {
        insertStatus(
                1,
                "active",
                ValidationRules.allowedValuesIgnoreCase(
                        "ACTIVE", "INACTIVE", "BLOCKED"));

        assertEquals("active", readStatus(1));
    }

    /**
     * Verifies that case-insensitive comparison does not weaken the whitelist:
     * an unrelated value must still fail validation and must not reach H2.
     */
    @Test
    void allowedValuesIgnoreCaseShouldPreventUnknownValueInsert()
            throws SQLException {
        assertThrows(
                IllegalArgumentException.class,
                () -> insertStatus(
                        1,
                        "PENDING",
                        ValidationRules.allowedValuesIgnoreCase(
                                "ACTIVE", "INACTIVE", "BLOCKED")));

        assertFalse(recordExists(1));
    }

    /**
     * Executes the INSERT used by each scenario. The status parameter is bound
     * through the production validation/binder utility rather than directly via
     * PreparedStatement#setString.
     */
    private void insertStatus(int id,
                              String status,
                              ValidationRule<String> statusRule) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO ACCOUNT_STATUS (ID, STATUS) VALUES (?, ?)")) {

            PreparedStatementBinder.bind(
                    statement,
                    SqlParameter.required("id", id, Types.INTEGER,
                            ValidationRules.positiveInteger()),
                    SqlParameter.required("status", status, Types.VARCHAR,
                            ValidationRules.notBlank(),
                            statusRule));

            statement.executeUpdate();
        }
    }

    /**
     * Reads the stored status back from H2 to prove that successful validation
     * resulted in an actual database write.
     */
    private String readStatus(int id) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT STATUS FROM ACCOUNT_STATUS WHERE ID = ?")) {
            statement.setInt(1, id);

            try (ResultSet resultSet = statement.executeQuery()) {
                assertTrue(resultSet.next());
                return resultSet.getString("STATUS");
            }
        }
    }

    /**
     * Checks database state after a validation failure. A false result proves
     * that the rejected value never reached SQL execution.
     */
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
