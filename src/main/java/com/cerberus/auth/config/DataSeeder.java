package com.cerberus.auth.config;

import com.cerberus.auth.entity.Permission;
import com.cerberus.auth.entity.Role;
import com.cerberus.auth.entity.User;
import com.cerberus.auth.repository.PermissionRepository;
import com.cerberus.auth.repository.RoleRepository;
import com.cerberus.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

// CommandLineRunner beans run once, automatically, right after the app
// starts. This is a common pattern for "make sure baseline data exists"
// tasks -- in a real production system you'd likely use a proper migration
// tool (Flyway/Liquibase) for this instead, but for local dev this is
// simple and transparent.
@Component
@RequiredArgsConstructor
public class DataSeeder implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseGet(() -> roleRepository.save(Role.builder().name("ROLE_USER").build()));

        Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                .orElseGet(() -> roleRepository.save(Role.builder().name("ROLE_ADMIN").build()));

        // "resource:action" naming -- this convention is what makes
        // @PreAuthorize("hasAuthority('user:delete')") read like plain
        // English instead of a magic string.
        Set<Permission> adminPermissions = Stream.of("user:read", "user:write", "user:delete", "role:manage")
                .map(name -> permissionRepository.findByName(name)
                        .orElseGet(() -> permissionRepository.save(Permission.builder().name(name).build())))
                .collect(Collectors.toSet());

        if (!adminRole.getPermissions().containsAll(adminPermissions)) {
            adminRole.getPermissions().addAll(adminPermissions);
            roleRepository.save(adminRole);
        }

        // Bootstrap admin account -- dev-only convenience so there's SOME
        // way to reach admin-only endpoints without a manual DB edit.
        // A real system would provision this via a controlled deploy step,
        // not a hardcoded seed.
        if (userRepository.findByEmail("admin@cerberus.dev").isEmpty()) {
            User admin = User.builder()
                    .email("admin@cerberus.dev")
                    .password(passwordEncoder.encode("AdminPass123!"))
                    .enabled(true)
                    .roles(Set.of(adminRole))
                    .build();
            userRepository.save(admin);
        }
    }
}
