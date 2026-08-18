package com.chetankhandave.utility.jdbc;

import java.sql.PreparedStatement;
import java.sql.SQLException;

/**
 * Utility for validating and binding ordered {@link SqlParameter} values to a
 * JDBC {@link PreparedStatement}.
 *
 * <p>Parameters are bound in the same order in which they are supplied. The
 * first {@code SqlParameter} maps to JDBC index 1, the second to index 2, and
 * so on.</p>
 */
public final class PreparedStatementBinder {

    private PreparedStatementBinder() {
        // Prevent instantiation of this utility class.
    }

    /**
     * Validates and binds all supplied parameters to the prepared statement.
     *
     * <p>Each {@link SqlParameter} performs its own nullability and custom-rule
     * validation before it is bound.</p>
     *
     * @param preparedStatement prepared statement that receives the parameters
     * @param parameters parameters in the exact order of SQL placeholders
     * @throws SQLException when JDBC binding fails
     * @throws IllegalArgumentException if the statement, parameter array, or an
     *                                  individual parameter is {@code null}, or
     *                                  when a parameter fails validation
     */
    public static void bind(PreparedStatement preparedStatement,
                            SqlParameter<?>... parameters) throws SQLException {

        if (preparedStatement == null) {
            throw new IllegalArgumentException("PreparedStatement must not be null");
        }

        if (parameters == null) {
            throw new IllegalArgumentException("Parameters must not be null");
        }

        for (int i = 0; i < parameters.length; i++) {
            SqlParameter<?> parameter = parameters[i];

            if (parameter == null) {
                throw new IllegalArgumentException(
                        "SQL parameter at index " + (i + 1) + " must not be null");
            }

            // JDBC parameter indexes start at 1, while Java array indexes start at 0.
            parameter.bind(preparedStatement, i + 1);
        }
    }
}
