package com.chetankhandave.utility.jdbc;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Represents one JDBC {@link PreparedStatement} parameter together with its
 * SQL type, nullability requirement, and optional validation rules.
 *
 * <p>A parameter can be declared as either {@link #required(String, Object, int, ValidationRule[])}
 * or {@link #nullable(String, Object, int, ValidationRule[])}. Validation is
 * performed immediately before the value is bound to the prepared statement.</p>
 *
 * <p>Example:</p>
 * <pre>
 * SqlParameter.required(
 *         "customerId",
 *         customerId,
 *         Types.VARCHAR,
 *         ValidationRules.notBlank(),
 *         ValidationRules.maxLength(20));
 * </pre>
 *
 * @param <T> Java type of the parameter value
 */
public final class SqlParameter<T> {

    private final String name;
    private final T value;
    private final int sqlType;
    private final boolean nullable;
    private final List<ValidationRule<T>> validationRules;

    @SafeVarargs
    private SqlParameter(String name, T value, int sqlType, boolean nullable,
                         ValidationRule<T>... validationRules) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Parameter name must not be null or empty");
        }

        this.name = name;
        this.value = value;
        this.sqlType = sqlType;
        this.nullable = nullable;
        this.validationRules = validationRules == null
                ? Collections.<ValidationRule<T>>emptyList()
                : Arrays.asList(validationRules);
    }

    /**
     * Creates a mandatory SQL parameter.
     *
     * @param name parameter name used in validation error messages
     * @param value value to bind; must not be {@code null}
     * @param sqlType JDBC SQL type from {@link java.sql.Types}
     * @param validationRules optional rules applied when the value is non-null
     * @param <T> Java type of the value
     * @return configured SQL parameter
     */
    @SafeVarargs
    public static <T> SqlParameter<T> required(String name, T value, int sqlType,
                                                ValidationRule<T>... validationRules) {
        return new SqlParameter<T>(name, value, sqlType, false, validationRules);
    }

    /**
     * Creates an optional SQL parameter. A {@code null} value is bound using
     * {@link PreparedStatement#setNull(int, int)}.
     *
     * @param name parameter name used in validation error messages
     * @param value value to bind; may be {@code null}
     * @param sqlType JDBC SQL type from {@link java.sql.Types}
     * @param validationRules optional rules applied only when the value is non-null
     * @param <T> Java type of the value
     * @return configured SQL parameter
     */
    @SafeVarargs
    public static <T> SqlParameter<T> nullable(String name, T value, int sqlType,
                                                ValidationRule<T>... validationRules) {
        return new SqlParameter<T>(name, value, sqlType, true, validationRules);
    }

    /**
     * Validates this parameter and binds it at the specified JDBC index.
     *
     * @param preparedStatement statement receiving the value
     * @param index one-based JDBC parameter index
     * @throws SQLException when JDBC binding fails
     * @throws IllegalArgumentException when the value violates its contract
     */
    void bind(PreparedStatement preparedStatement, int index) throws SQLException {
        validate();

        if (value == null) {
            preparedStatement.setNull(index, sqlType);
            return;
        }

        preparedStatement.setObject(index, value, sqlType);
    }

    /**
     * Checks nullability first and then applies every configured validation rule.
     * Nullable parameters skip custom rules when their value is {@code null}.
     */
    private void validate() {
        if (value == null) {
            if (!nullable) {
                throw new IllegalArgumentException(name + " must not be null");
            }
            return;
        }

        for (ValidationRule<T> rule : validationRules) {
            if (rule == null) {
                throw new IllegalArgumentException(
                        "Validation rule for parameter '" + name + "' must not be null");
            }

            if (!rule.isValid(value)) {
                throw new IllegalArgumentException(name + ": " + rule.getMessage());
            }
        }
    }
}
