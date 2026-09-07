package com.chetankhandave.utility.jdbc;

import org.junit.jupiter.api.Test;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class PreparedStatementBinderTest {

    @Test
    void shouldBindRequiredNonNullParameter() throws SQLException {
        PreparedStatement statement = mock(PreparedStatement.class);

        PreparedStatementBinder.bind(
                statement,
                SqlParameter.required("name", "Chetan", Types.VARCHAR));

        verify(statement).setObject(1, "Chetan", Types.VARCHAR);
    }

    @Test
    void shouldBindNullableNullParameterUsingSetNull() throws SQLException {
        PreparedStatement statement = mock(PreparedStatement.class);

        PreparedStatementBinder.bind(
                statement,
                SqlParameter.nullable("description", null, Types.VARCHAR));

        verify(statement).setNull(1, Types.VARCHAR);
    }

    @Test
    void shouldRejectNullRequiredValueBeforeBinding() throws SQLException {
        PreparedStatement statement = mock(PreparedStatement.class);

        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> PreparedStatementBinder.bind(
                        statement,
                        SqlParameter.required("customerId", null, Types.VARCHAR)));

        assertEquals("customerId must not be null", exception.getMessage());
        verify(statement, never()).setObject(1, null, Types.VARCHAR);
    }

    @Test
    void shouldApplyAllValidationRules() throws SQLException {
        PreparedStatement statement = mock(PreparedStatement.class);

        PreparedStatementBinder.bind(
                statement,
                SqlParameter.required(
                        "customerId",
                        "CUST01",
                        Types.VARCHAR,
                        ValidationRules.notBlank(),
                        ValidationRules.maxLength(20)));

        verify(statement).setObject(1, "CUST01", Types.VARCHAR);
    }

    @Test
    void shouldRejectValueWhenAnyValidationRuleFails() throws SQLException {
        PreparedStatement statement = mock(PreparedStatement.class);

        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> PreparedStatementBinder.bind(
                        statement,
                        SqlParameter.required(
                                "customerId",
                                "123456",
                                Types.VARCHAR,
                                ValidationRules.maxLength(5))));

        assertEquals("customerId: length must not exceed 5", exception.getMessage());
    }

    @Test
    void shouldSkipCustomRulesForNullableNullValue() throws SQLException {
        PreparedStatement statement = mock(PreparedStatement.class);
        ValidationRule<String> ruleThatWouldFail = new ValidationRule<String>(
                value -> false,
                "always fails");

        PreparedStatementBinder.bind(
                statement,
                SqlParameter.nullable(
                        "description",
                        null,
                        Types.VARCHAR,
                        ruleThatWouldFail));

        verify(statement).setNull(1, Types.VARCHAR);
    }

    @Test
    void shouldRejectNullValidationRule() throws SQLException {
        PreparedStatement statement = mock(PreparedStatement.class);

        @SuppressWarnings("unchecked")
        ValidationRule<String> nullRule = null;

        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> PreparedStatementBinder.bind(
                        statement,
                        SqlParameter.required(
                                "name",
                                "Chetan",
                                Types.VARCHAR,
                                nullRule)));

        assertEquals("Validation rule for parameter 'name' must not be null",
                exception.getMessage());
    }

    @Test
    void shouldBindParametersInSqlPlaceholderOrder() throws SQLException {
        PreparedStatement statement = mock(PreparedStatement.class);

        PreparedStatementBinder.bind(
                statement,
                SqlParameter.required("name", "Chetan", Types.VARCHAR),
                SqlParameter.required("age", 35, Types.INTEGER),
                SqlParameter.nullable("description", null, Types.VARCHAR));

        verify(statement).setObject(1, "Chetan", Types.VARCHAR);
        verify(statement).setObject(2, 35, Types.INTEGER);
        verify(statement).setNull(3, Types.VARCHAR);
    }

    @Test
    void shouldRejectNullPreparedStatement() {
        assertThrows(
                IllegalArgumentException.class,
                () -> PreparedStatementBinder.bind(
                        null,
                        SqlParameter.required("name", "Chetan", Types.VARCHAR)));
    }

    @Test
    void shouldRejectNullParameterArray() {
        PreparedStatement statement = mock(PreparedStatement.class);

        assertThrows(
                IllegalArgumentException.class,
                () -> PreparedStatementBinder.bind(statement, (SqlParameter<?>[]) null));
    }

    @Test
    void shouldRejectNullParameterInsideArray() {
        PreparedStatement statement = mock(PreparedStatement.class);

        assertThrows(
                IllegalArgumentException.class,
                () -> PreparedStatementBinder.bind(
                        statement,
                        SqlParameter.required("name", "Chetan", Types.VARCHAR),
                        null));
    }

    @Test
    void shouldRejectNullOrBlankParameterName() {
        assertThrows(IllegalArgumentException.class,
                () -> SqlParameter.required(null, "value", Types.VARCHAR));

        assertThrows(IllegalArgumentException.class,
                () -> SqlParameter.required("", "value", Types.VARCHAR));

        assertThrows(IllegalArgumentException.class,
                () -> SqlParameter.required("   ", "value", Types.VARCHAR));
    }

    @Test
    void shouldSupportCustomPredicateRule() throws SQLException {
        PreparedStatement statement = mock(PreparedStatement.class);
        ValidationRule<String> startsWithReq = new ValidationRule<String>(
                value -> value.startsWith("REQ-"),
                "must start with REQ-");

        PreparedStatementBinder.bind(
                statement,
                SqlParameter.required(
                        "requestReferenceNumber",
                        "REQ-1001",
                        Types.VARCHAR,
                        startsWithReq));

        verify(statement).setObject(1, "REQ-1001", Types.VARCHAR);
    }
}
