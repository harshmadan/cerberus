package com.cerberus.auth.repository;

import com.cerberus.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {

    // Spring Data JPA parses this method name and writes the SQL for you:
    // "findByEmail" -> SELECT * FROM users WHERE email = ?
    // No implementation needed -- this is one of JPA's more magical parts,
    // worth knowing so it doesn't feel like it's reading your mind.
    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);
}
