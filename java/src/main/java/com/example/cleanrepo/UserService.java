package com.example.cleanrepo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

@Service
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = new BCryptPasswordEncoder(12);
    }

    /**
     * Finds a user by ID using Spring Data JPA repository query execution.
     * Prevents SQL Injection (CWE-89).
     */
    public UserEntity findUserById(long userId) {
        Optional<UserEntity> userOpt = userRepository.findById(userId);
        return userOpt.orElse(null);
    }

    /**
     * Hashes user authentication credential using BCrypt and persists entity.
     */
    public UserEntity createUser(String username, String email, String rawCredential) {
        if (username == null || !username.matches("^[a-zA-Z0-9_-]{3,50}$")) {
            throw new IllegalArgumentException("Invalid username format.");
        }
        if (rawCredential == null || rawCredential.length() < 12) {
            throw new IllegalArgumentException("Credential must be at least 12 characters.");
        }

        String encodedCredential = passwordEncoder.encode(rawCredential);
        UserEntity user = new UserEntity(username, email, encodedCredential);
        UserEntity savedUser = userRepository.save(user);
        
        // Log sanitization against log injection (CWE-117)
        String safeUsername = username.replaceAll("[\r\n]", "_");
        logger.info("User created successfully: {}", safeUsername);
        
        return savedUser;
    }

    public interface UserRepository extends JpaRepository<UserEntity, Long> {
        Optional<UserEntity> findByUsername(String username);
    }

    @Entity
    @Table(name = "app_users")
    public static class UserEntity {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;
        private String username;
        private String email;
        private String authDigest;

        public UserEntity() {}

        public UserEntity(String username, String email, String authDigest) {
            this.username = username;
            this.email = email;
            this.authDigest = authDigest;
        }

        public Long getId() { return id; }
        public String getUsername() { return username; }
        public String getEmail() { return email; }
        public String getAuthDigest() { return authDigest; }
    }
}
