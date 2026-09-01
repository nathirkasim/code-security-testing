package com.example.cleanrepo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

@Service
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);
    private final DataSource dataSource;
    private final PasswordEncoder passwordEncoder;

    public UserService(DataSource dataSource) {
        this.dataSource = dataSource;
        this.passwordEncoder = new BCryptPasswordEncoder(12);
    }

    /**
     * Finds a user by ID using parameterized PreparedStatements.
     * Prevents SQL Injection (CWE-89).
     */
    public UserRecord findUserById(long userId) throws SQLException {
        String sql = "SELECT id, username, email FROM users WHERE id = ?";
        
        try (Connection conn = dataSource.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setLong(1, userId);
            
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return new UserRecord(
                        rs.getLong("id"),
                        rs.getString("username"),
                        rs.getString("email")
                    );
                }
            }
        }
        return null;
    }

    /**
     * Hashes password using BCrypt and saves user with parameterized query.
     */
    public boolean createUser(String username, String email, String rawPassword) throws SQLException {
        if (username == null || !username.matches("^[a-zA-Z0-9_-]{3,50}$")) {
            throw new IllegalArgumentException("Invalid username format.");
        }
        if (rawPassword == null || rawPassword.length() < 12) {
            throw new IllegalArgumentException("Password must be at least 12 characters.");
        }

        String hashedPassword = passwordEncoder.encode(rawPassword);
        String sql = "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)";

        try (Connection conn = dataSource.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, username);
            pstmt.setString(2, email);
            pstmt.setString(3, hashedPassword);
            
            int rowsAffected = pstmt.executeUpdate();
            
            // Log sanitization against log injection (CWE-117)
            String safeUsername = username.replaceAll("[\r\n]", "_");
            logger.info("User created successfully: {}", safeUsername);
            
            return rowsAffected > 0;
        }
    }

    public static class UserRecord {
        private final long id;
        private final String username;
        private final String email;

        public UserRecord(long id, String username, String email) {
            this.id = id;
            this.username = username;
            this.email = email;
        }

        public long getId() { return id; }
        public String getUsername() { return username; }
        public String getEmail() { return email; }
    }
}
