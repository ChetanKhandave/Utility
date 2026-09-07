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

/**
 * Focused unit tests for {@link PreparedStatementBinder} and the binding behavior
 * of {@link SqlParameter}.
 *
 * <p>Mockito is intentionally used here because these tests verify exact JDBC
 * method calls, parameter indexes, and failure-before-binding behavior. Real
 * database interaction is covered separately by the H2 integration tests.</p>
 */
class PreparedStatementBinderTest {

    /** Verifies that a non-null required value is bound with the expected SQL type. */
    @Test
    void shouldBindRequiredNonNullParameter() throws SQLException {
        PreparedStatement statement = mock(PreparedStatement.class);
        PreparedStatementBinder.bind(statement,
                SqlParameter.required("name", "Chetan", Types.VARCHAR));
        verify(statement).setObject(1, "Chetan", Types.VARCHAR);
    }

    /** Verifies that an allowed null value is converted to JDBC setNull. */
    @Test
    void shouldBindNullableNullParameterUsingSetNull() throws SQLException {
        PreparedStatement statement = mock(PreparedStatement.class);
        PreparedStatementBinder.bind(statement,
                SqlParameter.nullable("description", null, Types.VARCHAR));
        verify(statement).setNull(1, Types.VARCHAR);
    }

    /** Ensures required null values fail validation before any JDBC value is bound. */
    @Test
    void shouldRejectNullRequiredValueBeforeBinding() throws SQLException {
        PreparedStatement statement = mock(PreparedStatement.class);
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> PreparedStatementBinder.bind(statement,
                        SqlParameter.required("customerId", null, Types.VARCHAR)));
        assertEquals("customerId must not be null", exception.getMessage());
        verify(statement, never()).setObject(1, null, Types.VARCHAR);
    }

    /** Verifies that multiple validation rules may be combined for one parameter. */
    @Test
    void shouldApplyAllValidationRules() throws SQLException {
        PreparedStatement statement = mock(PreparedStatement.class);
        PreparedStatementBinder.bind(statement,
                SqlParameter.required("customerId", "CUST01", Types.VARCHAR,
                        ValidationRules.notBlank(), ValidationRules.maxLength(20)));
        verify(statement).setObject(1, "CUST01", Types.VARCHAR);
    }

    /** Ensures binding is aborted when any one of the configured rules fails. */
    @Test
    void shouldRejectValueWhenAnyValidationRuleFails() throws SQLException {
        PreparedStatement statement = mock(PreparedStatement.class);
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> PreparedStatementBinder.bind(statement,
                        SqlParameter.required("customerId", "123456", Types.VARCHAR,
                                ValidationRules.maxLength(5))));
        assertEquals("customerId: length must not exceed 5", exception.getMessage());
    }

    /** Verifies that custom rules are skipped when a nullable parameter is actually null. */
    @Test
    void shouldSkipCustomRulesForNullableNullValue() throws SQLException {
        PreparedStatement statement = mock(PreparedStatement.class);
        ValidationRule<String> ruleThatWouldFail = new ValidationRule<String>(
                value -> false, "always fails");
        PreparedStatementBinder.bind(statement,
                SqlParameter.nullable("description", null, Types.VARCHAR, ruleThatWouldFail));
        verify(statement).setNull(1, Types.VARCHAR);
    }

    /** Ensures a null ValidationRule entry is reported clearly instead of causing an obscure NPE. */
    @Test
    void shouldRejectNullValidationRule() throws SQLException {
        PreparedStatement statement = mock(PreparedStatement.class);
        @SuppressWarnings("unchecked")
        ValidationRule<String> nullRule = null;
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> PreparedStatementBinder.bind(statement,
                        SqlParameter.required("name", "Chetan", Types.VARCHAR, nullRule)));
        assertEquals("Validation rule for parameter 'name' must not be null",
                exception.getMessage());
    }

    /** Verifies that Java argument order maps exactly to JDBC placeholder indexes 1..N. */
    @Test
    void shouldBindParametersInSqlPlaceholderOrder() throws SQLException {
        PreparedStatement statement = mock(PreparedStatement.class);
        PreparedStatementBinder.bind(statement,
                SqlParameter.required("name", "Chetan", Types.VARCHAR),
                SqlParameter.required("age", 35, Types.INTEGER),
                SqlParameter.nullable("description", null, Types.VARCHAR));
        verify(statement).setObject(1, "Chetan", Types.VARCHAR);
        verify(statement).setObject(2, 35, Types.INTEGER);
        verify(statement).setNull(3, Types.VARCHAR);
    }

    /** Covers the invalid API usage scenario where the PreparedStatement itself is null. */
    @Test
    void shouldRejectNullPreparedStatement() {
        assertThrows(IllegalArgumentException.class,
                () -> PreparedStatementBinder.bind(null,
                        SqlParameter.required("name", "Chetan", Types.VARCHAR)));
    }

    /** Covers the invalid API usage scenario where the complete parameter array is null. */
    @Test
    void shouldRejectNullParameterArray() {
        PreparedStatement statement = mock(PreparedStatement.class);
        assertThrows(IllegalArgumentException.class,
                () -> PreparedStatementBinder.bind(statement, (SqlParameter<?>[]) null));
    }

    /** Ensures an accidental null element inside an otherwise valid parameter array is rejected. */
    @Test
    void shouldRejectNullParameterInsideArray() {
        PreparedStatement statement = mock(PreparedStatement.class);
        assertThrows(IllegalArgumentException.class,
                () -> PreparedStatementBinder.bind(statement,
                        SqlParameter.required("name", "Chetan", Types.VARCHAR), null));
    }

    /** Verifies parameter names must be meaningful because they are used in validation diagnostics. */
    @Test
    void shouldRejectNullOrBlankParameterName() {
        assertThrows(IllegalArgumentException.class,
                () -> SqlParameter.required(null, "value", Types.VARCHAR));
        assertThrows(IllegalArgumentException.class,
                () -> SqlParameter.required("", "value", Types.VARCHAR));
        assertThrows(IllegalArgumentException.class,
                () -> SqlParameter.required("   ", "value", Types.VARCHAR));
    }

    /** Demonstrates that callers can supply a field-specific predicate in addition to built-in rules. */
    @Test
    void shouldSupportCustomPredicateRule() throws SQLException {
        PreparedStatement statement = mock(PreparedStatement.class);
        ValidationRule<String> startsWithReq = new ValidationRule<String>(
                value -> value.startsWith("REQ-"), "must start with REQ-");
        PreparedStatementBinder.bind(statement,
                SqlParameter.required("requestReferenceNumber", "REQ-1001",
                        Types.VARCHAR, startsWithReq));
        verify(statement).setObject(1, "REQ-1001", Types.VARCHAR);
    }
}
