package com.chetankhandave.utility.jdbc.client;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration tests for {@link JdbcParameterValidationClient} using a real H2
 * in-memory database.
 *
 * <p>Unlike the unit tests, this class intentionally does not mock
 * {@link Connection}, {@link PreparedStatement}, or {@link ResultSet}. Its
 * purpose is to verify that validation, JDBC parameter binding, SQL execution,
 * and persisted data work together through an actual JDBC driver.</p>
 */
class JdbcParameterValidationClientIntegrationTest {

    private Connection connection;
    private JdbcParameterValidationClient client;

    /**
     * Creates an isolated in-memory database and schema before every test so
     * each scenario starts from a known database state.
     */
    @BeforeEach
    void setUp() throws SQLException {
        connection = DriverManager.getConnection("jdbc:h2:mem:jdbc_validation;DB_CLOSE_DELAY=-1");
        client = new JdbcParameterValidationClient();

        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP TABLE IF EXISTS REQUEST_DETAILS");
            statement.execute("DROP TABLE IF EXISTS CUSTOMER");
            statement.execute("CREATE TABLE CUSTOMER ("
                    + "CUSTOMER_ID VARCHAR(20) PRIMARY KEY, "
                    + "NAME VARCHAR(100) NOT NULL, "
                    + "DESCRIPTION VARCHAR(500), "
                    + "AGE INT NOT NULL)");
            statement.execute("CREATE TABLE REQUEST_DETAILS ("
                    + "REQUEST_REFERENCE_NUMBER VARCHAR(50) PRIMARY KEY)");
        }
    }

    /**
     * Closes the real JDBC connection after each test to avoid leaking database
     * resources between integration-test scenarios.
     */
    @AfterEach
    void tearDown() throws SQLException {
        if (connection != null) {
            connection.close();
        }
    }

    /**
     * Verifies the complete update flow for valid values: validation succeeds,
     * a real PreparedStatement is populated, SQL executes, and the expected
     * values are persisted in the database.
     */
    @Test
    void updateCustomerShouldPersistValidValuesUsingRealJdbc() throws SQLException {
        insertCustomer("CUST001", "Old Name", "Old description", 30);

        int updatedRows = client.updateCustomer(
                connection, "CUST001", "Chetan", "Premium customer", 35);

        assertEquals(1, updatedRows);

        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT NAME, DESCRIPTION, AGE FROM CUSTOMER WHERE CUSTOMER_ID = ?")) {
            statement.setString(1, "CUST001");
            try (ResultSet resultSet = statement.executeQuery()) {
                assertTrue(resultSet.next());
                assertEquals("Chetan", resultSet.getString("NAME"));
                assertEquals("Premium customer", resultSet.getString("DESCRIPTION"));
                assertEquals(35, resultSet.getInt("AGE"));
                assertFalse(resultSet.next());
            }
        }
    }

    /**
     * Covers the nullable-parameter path with a real JDBC driver. A Java null
     * description must be bound as SQL NULL and stored as NULL by H2.
     */
    @Test
    void updateCustomerShouldPersistSqlNullForNullableDescription() throws SQLException {
        insertCustomer("CUST001", "Old Name", "Old description", 30);

        int updatedRows = client.updateCustomer(
                connection, "CUST001", "Chetan", null, 35);

        assertEquals(1, updatedRows);

        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT DESCRIPTION FROM CUSTOMER WHERE CUSTOMER_ID = ?")) {
            statement.setString(1, "CUST001");
            try (ResultSet resultSet = statement.executeQuery()) {
                assertTrue(resultSet.next());
                assertNull(resultSet.getString("DESCRIPTION"));
            }
        }
    }

    /**
     * Verifies that invalid input is rejected before SQL execution. The existing
     * database row must remain unchanged when validation fails.
     */
    @Test
    void updateCustomerShouldNotModifyDatabaseWhenValidationFails() throws SQLException {
        insertCustomer("CUST001", "Original Name", "Original description", 30);

        assertThrows(
                IllegalArgumentException.class,
                () -> client.updateCustomer(connection, "CUST001", "   ", "Changed", 40));

        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT NAME, DESCRIPTION, AGE FROM CUSTOMER WHERE CUSTOMER_ID = ?")) {
            statement.setString(1, "CUST001");
            try (ResultSet resultSet = statement.executeQuery()) {
                assertTrue(resultSet.next());
                assertEquals("Original Name", resultSet.getString("NAME"));
                assertEquals("Original description", resultSet.getString("DESCRIPTION"));
                assertEquals(30, resultSet.getInt("AGE"));
            }
        }
    }

    /**
     * Verifies a valid custom predicate rule through the real database path.
     * A reference beginning with REQ- must be inserted successfully.
     */
    @Test
    void insertRequestShouldPersistValidReferenceUsingRealJdbc() throws SQLException {
        int insertedRows = client.insertRequest(connection, "REQ-1001");

        assertEquals(1, insertedRows);

        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT REQUEST_REFERENCE_NUMBER FROM REQUEST_DETAILS WHERE REQUEST_REFERENCE_NUMBER = ?")) {
            statement.setString(1, "REQ-1001");
            try (ResultSet resultSet = statement.executeQuery()) {
                assertTrue(resultSet.next());
                assertEquals("REQ-1001", resultSet.getString("REQUEST_REFERENCE_NUMBER"));
            }
        }
    }

    /**
     * Covers the failing custom-predicate scenario. An invalid prefix must be
     * rejected before insertion and the table must remain empty.
     */
    @Test
    void insertRequestShouldNotInsertWhenCustomValidationFails() throws SQLException {
        assertThrows(
                IllegalArgumentException.class,
                () -> client.insertRequest(connection, "ABC-1001"));

        try (Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery("SELECT COUNT(*) FROM REQUEST_DETAILS")) {
            assertTrue(resultSet.next());
            assertEquals(0, resultSet.getInt(1));
        }
    }

    /**
     * Covers a genuine database constraint failure. Validation accepts the
     * value, but inserting the same primary key twice must still surface the
     * SQLException produced by the database.
     */
    @Test
    void insertRequestShouldPropagateRealDatabaseConstraintViolation() throws SQLException {
        client.insertRequest(connection, "REQ-1001");

        assertThrows(
                SQLException.class,
                () -> client.insertRequest(connection, "REQ-1001"));
    }

    /**
     * Inserts fixture data directly through JDBC so update tests can focus on
     * the behavior of the client method under test.
     */
    private void insertCustomer(String customerId,
                                String name,
                                String description,
                                int age) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO CUSTOMER (CUSTOMER_ID, NAME, DESCRIPTION, AGE) VALUES (?, ?, ?, ?)")) {
            statement.setString(1, customerId);
            statement.setString(2, name);
            statement.setString(3, description);
            statement.setInt(4, age);
            statement.executeUpdate();
        }
    }
}
