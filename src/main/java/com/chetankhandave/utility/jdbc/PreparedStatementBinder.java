package com.chetankhandave.utility.jdbc;

import java.sql.PreparedStatement;
import java.sql.SQLException;

/**
 * Utility for binding ordered {@link SqlParameter} values to a
 * {@link PreparedStatement}.
 */
public final class PreparedStatementBinder {

    private PreparedStatementBinder() {
        // Utility class
    }

    public static void bind(PreparedStatement preparedStatement,
                            SqlParameter... parameters) throws SQLException {

        if (preparedStatement == null) {
            throw new IllegalArgumentException("PreparedStatement must not be null");
        }

        if (parameters == null) {
            throw new IllegalArgumentException("Parameters must not be null");
        }

        for (int i = 0; i < parameters.length; i++) {
            SqlParameter parameter = parameters[i];

            if (parameter == null) {
                throw new IllegalArgumentException(
                        "SQL parameter at index " + (i + 1) + " must not be null");
            }

            parameter.bind(preparedStatement, i + 1);
        }
    }
}
