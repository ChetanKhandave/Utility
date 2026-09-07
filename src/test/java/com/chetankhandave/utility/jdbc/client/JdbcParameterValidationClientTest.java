package com.chetankhandave.utility.jdbc.client;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JdbcParameterValidationClientTest {

    private Connection connection;
    private PreparedStatement statement;
    private JdbcParameterValidationClient client;

    @BeforeEach
    void setUp() throws SQLException {
        connection = mock(Connection.class);
        statement = mock(PreparedStatement.class);
        client = new JdbcParameterValidationClient();

        when(connection.prepareStatement(anyString())).thenReturn(statement);
        when(statement.executeUpdate()).thenReturn(1);
    }

    @Test
    void updateCustomerShouldBindValidValuesAndExecute() throws SQLException {
        int rows = client.updateCustomer(
                connection,
                "CUST001",
                "Chetan",
                "Premium customer",
                35);

        assertEquals(1, rows);
        verify(statement).setObject(1, "Chetan", Types.VARCHAR);
        verify(statement).setObject(2, "Premium customer", Types.VARCHAR);
        verify(statement).setObject(3, 35, Types.INTEGER);
        verify(statement).setObject(4, "CUST001", Types.VARCHAR);
        verify(statement).executeUpdate();
        verify(statement).close();
    }

    @Test
    void updateCustomerShouldAllowNullDescription() throws SQLException {
        client.updateCustomer(connection, "CUST001", "Chetan", null, 35);

        verify(statement).setNull(2, Types.VARCHAR);
        verify(statement).executeUpdate();
    }

    @Test
    void updateCustomerShouldRejectNullName() throws SQLException {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> client.updateCustomer(connection, "CUST001", null, null, 35));

        assertEquals("name must not be null", exception.getMessage());
        verify(statement, never()).executeUpdate();
    }

    @Test
    void updateCustomerShouldRejectBlankName() throws SQLException {
        assertThrows(
                IllegalArgumentException.class,
                () -> client.updateCustomer(connection, "CUST001", "   ", null, 35));

        verify(statement, never()).executeUpdate();
    }

    @Test
    void updateCustomerShouldRejectNameLongerThan100Characters() throws SQLException {
        String longName = repeat('A', 101);

        assertThrows(
                IllegalArgumentException.class,
                () -> client.updateCustomer(connection, "CUST001", longName, null, 35));

        verify(statement, never()).executeUpdate();
    }

    @Test
    void updateCustomerShouldAcceptNameExactly100Characters() throws SQLException {
        String name = repeat('A', 100);

        client.updateCustomer(connection, "CUST001", name, null, 35);

        verify(statement).executeUpdate();
    }

    @Test
    void updateCustomerShouldRejectDescriptionLongerThan500Characters() throws SQLException {
        String description = repeat('D', 501);

        assertThrows(
                IllegalArgumentException.class,
                () -> client.updateCustomer(connection, "CUST001", "Chetan", description, 35));

        verify(statement, never()).executeUpdate();
    }

    @Test
    void updateCustomerShouldAcceptAgeAtMinimumBoundary() throws SQLException {
        client.updateCustomer(connection, "CUST001", "Chetan", null, 18);

        verify(statement).executeUpdate();
    }

    @Test
    void updateCustomerShouldAcceptAgeAtMaximumBoundary() throws SQLException {
        client.updateCustomer(connection, "CUST001", "Chetan", null, 100);

        verify(statement).executeUpdate();
    }

    @Test
    void updateCustomerShouldRejectAgeBelowMinimum() throws SQLException {
        assertThrows(
                IllegalArgumentException.class,
                () -> client.updateCustomer(connection, "CUST001", "Chetan", null, 17));

        verify(statement, never()).executeUpdate();
    }

    @Test
    void updateCustomerShouldRejectAgeAboveMaximum() throws SQLException {
        assertThrows(
                IllegalArgumentException.class,
                () -> client.updateCustomer(connection, "CUST001", "Chetan", null, 101));

        verify(statement, never()).executeUpdate();
    }

    @Test
    void updateCustomerShouldRejectNullAge() throws SQLException {
        assertThrows(
                IllegalArgumentException.class,
                () -> client.updateCustomer(connection, "CUST001", "Chetan", null, null));

        verify(statement, never()).executeUpdate();
    }

    @Test
    void updateCustomerShouldRejectBlankCustomerId() throws SQLException {
        assertThrows(
                IllegalArgumentException.class,
                () -> client.updateCustomer(connection, "   ", "Chetan", null, 35));

        verify(statement, never()).executeUpdate();
    }

    @Test
    void updateCustomerShouldRejectCustomerIdLongerThan20Characters() throws SQLException {
        String customerId = repeat('C', 21);

        assertThrows(
                IllegalArgumentException.class,
                () -> client.updateCustomer(connection, customerId, "Chetan", null, 35));

        verify(statement, never()).executeUpdate();
    }

    @Test
    void insertRequestShouldAcceptValidReferenceNumber() throws SQLException {
        int rows = client.insertRequest(connection, "REQ-1001");

        assertEquals(1, rows);
        verify(statement).setObject(1, "REQ-1001", Types.VARCHAR);
        verify(statement).executeUpdate();
    }

    @Test
    void insertRequestShouldRejectReferenceWithoutRequiredPrefix() throws SQLException {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> client.insertRequest(connection, "ABC-1001"));

        assertEquals("requestReferenceNumber: must start with REQ-", exception.getMessage());
        verify(statement, never()).executeUpdate();
    }

    @Test
    void insertRequestShouldRejectNullReferenceNumber() throws SQLException {
        assertThrows(
                IllegalArgumentException.class,
                () -> client.insertRequest(connection, null));

        verify(statement, never()).executeUpdate();
    }

    @Test
    void insertRequestShouldRejectReferenceLongerThan50Characters() throws SQLException {
        String reference = "REQ-" + repeat('1', 47);

        assertThrows(
                IllegalArgumentException.class,
                () -> client.insertRequest(connection, reference));

        verify(statement, never()).executeUpdate();
    }

    @Test
    void shouldPropagateSqlExceptionFromStatementCreation() throws SQLException {
        when(connection.prepareStatement(anyString()))
                .thenThrow(new SQLException("database unavailable"));

        SQLException exception = assertThrows(
                SQLException.class,
                () -> client.insertRequest(connection, "REQ-1001"));

        assertEquals("database unavailable", exception.getMessage());
    }

    @Test
    void shouldPropagateSqlExceptionFromExecution() throws SQLException {
        when(statement.executeUpdate()).thenThrow(new SQLException("update failed"));

        SQLException exception = assertThrows(
                SQLException.class,
                () -> client.insertRequest(connection, "REQ-1001"));

        assertEquals("update failed", exception.getMessage());
        verify(statement).close();
    }

    /**
     * Java 8 compatible helper because String#repeat was added in Java 11.
     */
    private static String repeat(char value, int count) {
        StringBuilder builder = new StringBuilder(count);
        for (int i = 0; i < count; i++) {
            builder.append(value);
        }
        return builder.toString();
    }
}
