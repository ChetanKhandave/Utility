package com.chetankhandave.utility.jdbc.client;

import com.chetankhandave.utility.jdbc.PreparedStatementBinder;
import com.chetankhandave.utility.jdbc.SqlParameter;
import com.chetankhandave.utility.jdbc.ValidationRule;
import com.chetankhandave.utility.jdbc.ValidationRules;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;

/**
 * Example client demonstrating how to validate JDBC parameters before executing
 * SQL statements.
 *
 * <p>The examples intentionally mix required parameters, nullable parameters,
 * reusable validation rules, and a custom predicate-based rule.</p>
 */
public class JdbcParameterValidationClient {

    /**
     * Updates customer information after validating every prepared-statement
     * argument.
     *
     * @param connection database connection used to create the statement
     * @param customerId mandatory customer identifier; non-blank, max 20 chars
     * @param name mandatory customer name; non-blank, max 100 chars
     * @param description optional customer description; max 500 chars when present
     * @param age mandatory customer age; allowed range 18 through 100
     * @return number of rows updated
     * @throws SQLException if statement creation or execution fails
     * @throws IllegalArgumentException if a parameter fails validation
     */
    public int updateCustomer(Connection connection,
                              String customerId,
                              String name,
                              String description,
                              Integer age) throws SQLException {

        String sql = "UPDATE CUSTOMER "
                + "SET NAME = ?, DESCRIPTION = ?, AGE = ? "
                + "WHERE CUSTOMER_ID = ?";

        try (PreparedStatement preparedStatement = connection.prepareStatement(sql)) {
            PreparedStatementBinder.bind(
                    preparedStatement,
                    SqlParameter.required(
                            "name",
                            name,
                            Types.VARCHAR,
                            ValidationRules.notBlank(),
                            ValidationRules.maxLength(100)),
                    SqlParameter.nullable(
                            "description",
                            description,
                            Types.VARCHAR,
                            ValidationRules.maxLength(500)),
                    SqlParameter.required(
                            "age",
                            age,
                            Types.INTEGER,
                            ValidationRules.integerRange(18, 100)),
                    SqlParameter.required(
                            "customerId",
                            customerId,
                            Types.VARCHAR,
                            ValidationRules.notBlank(),
                            ValidationRules.maxLength(20)));

            return preparedStatement.executeUpdate();
        }
    }

    /**
     * Inserts a request reference number using both reusable validation rules
     * and a custom predicate-based rule.
     *
     * @param connection database connection used to create the statement
     * @param requestReferenceNumber mandatory value that must start with {@code REQ-}
     * @return number of rows inserted
     * @throws SQLException if statement creation or execution fails
     * @throws IllegalArgumentException if the value fails validation
     */
    public int insertRequest(Connection connection,
                             String requestReferenceNumber) throws SQLException {

        String sql = "INSERT INTO REQUEST_DETAILS "
                + "(REQUEST_REFERENCE_NUMBER) VALUES (?)";

        // Custom rules are useful when a validation condition is specific to one field.
        ValidationRule<String> requestReferenceRule = new ValidationRule<String>(
                value -> value.startsWith("REQ-"),
                "must start with REQ-");

        try (PreparedStatement preparedStatement = connection.prepareStatement(sql)) {
            PreparedStatementBinder.bind(
                    preparedStatement,
                    SqlParameter.required(
                            "requestReferenceNumber",
                            requestReferenceNumber,
                            Types.VARCHAR,
                            ValidationRules.notBlank(),
                            ValidationRules.maxLength(50),
                            requestReferenceRule));

            return preparedStatement.executeUpdate();
        }
    }
}
