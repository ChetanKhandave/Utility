package com.chetankhandave.utility.jdbc;

import java.sql.PreparedStatement;
import java.sql.SQLException;

/**
 * Represents one JDBC prepared-statement parameter together with its SQL type
 * and nullability requirement.
 */
public final class SqlParameter {

    private final String name;
    private final Object value;
    private final int sqlType;
    private final boolean nullable;

    private SqlParameter(String name, Object value, int sqlType, boolean nullable) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Parameter name must not be null or empty");
        }

        this.name = name;
        this.value = value;
        this.sqlType = sqlType;
        this.nullable = nullable;
    }

    public static SqlParameter required(String name, Object value, int sqlType) {
        return new SqlParameter(name, value, sqlType, false);
    }

    public static SqlParameter nullable(String name, Object value, int sqlType) {
        return new SqlParameter(name, value, sqlType, true);
    }

    void bind(PreparedStatement preparedStatement, int index) throws SQLException {
        if (value == null) {
            if (!nullable) {
                throw new IllegalArgumentException(name + " must not be null");
            }

            preparedStatement.setNull(index, sqlType);
            return;
        }

        preparedStatement.setObject(index, value, sqlType);
    }
}
