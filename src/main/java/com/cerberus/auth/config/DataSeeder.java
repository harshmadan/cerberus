package com.cerberus.auth.config;

import com.cerberus.auth.entity.Role;
import com.cerberus.auth.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

// CommandLineRunner beans run once, automatically, right after the app
// starts. This is a common pattern for "make sure baseline data exists"
// tasks -- in a real production system you'd likely use a proper migration
// tool (Flyway/Liquibase) for this instead, but for local dev this is
// simple and transparent.
@Component
@RequiredArgsConstructor
public class DataSeeder implements CommandLineRunner {

    private final RoleRepository roleRepository;

    @Override
    public void run(String... args) {
        if (roleRepository.findByName("ROLE_USER").isEmpty()) {
            roleRepository.save(Role.builder().name("ROLE_USER").build());
        }
        if (roleRepository.findByName("ROLE_ADMIN").isEmpty()) {
            roleRepository.save(Role.builder().name("ROLE_ADMIN").build());
        }
    }
}
