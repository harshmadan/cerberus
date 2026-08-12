package com.cerberus.auth.service;

import com.cerberus.auth.dto.UserSummaryResponse;
import com.cerberus.auth.entity.Permission;
import com.cerberus.auth.entity.Role;
import com.cerberus.auth.entity.User;
import com.cerberus.auth.repository.PermissionRepository;
import com.cerberus.auth.repository.RoleRepository;
import com.cerberus.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AdminService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;

    public List<UserSummaryResponse> listUsers() {
        return userRepository.findAll().stream()
                .map(user -> UserSummaryResponse.builder()
                        .id(user.getId())
                        .email(user.getEmail())
                        .enabled(user.isEnabled())
                        .roles(user.getRoles().stream().map(Role::getName).collect(Collectors.toSet()))
                        .build())
                .toList();
    }

    public void assignRole(UUID userId, String roleName) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalStateException("User not found: " + userId));
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new IllegalStateException("Role not found: " + roleName));

        user.getRoles().add(role);
        userRepository.save(user);
        // Note what we did NOT do here: touch the user's existing JWT.
        // We can't -- it's already signed and out in the world. But since
        // CustomUserDetailsService re-reads roles from the DB on every
        // request, this change is effective on their very next API call,
        // regardless of how much time is left on their current token.
    }

    public void createPermission(String name) {
        if (permissionRepository.findByName(name).isPresent()) {
            throw new IllegalStateException("Permission already exists: " + name);
        }
        permissionRepository.save(Permission.builder().name(name).build());
    }

    public void assignPermissionToRole(UUID roleId, String permissionName) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new IllegalStateException("Role not found: " + roleId));
        Permission permission = permissionRepository.findByName(permissionName)
                .orElseThrow(() -> new IllegalStateException("Permission not found: " + permissionName));

        role.getPermissions().add(permission);
        roleRepository.save(role);
        // Same effect as above, one level up: everyone holding this role
        // gains the permission on their next request, no re-login needed.
    }
}
