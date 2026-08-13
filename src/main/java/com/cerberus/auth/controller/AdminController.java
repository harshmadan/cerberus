package com.cerberus.auth.controller;

import com.cerberus.auth.dto.*;
import com.cerberus.auth.service.AdminService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@Tag(name = "Admin", description = "RBAC management -- admin only")
public class AdminController {

    private final AdminService adminService;

    // Coarse-grained: "are you an admin at all." Fine for a broad,
    // low-risk read like listing users.
    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public List<UserSummaryResponse> listUsers() {
        return adminService.listUsers();
    }

    // Fine-grained: this specific action requires the specific permission,
    // not just "any admin." In practice most admins WILL have role:manage
    // (we seeded it that way), but this is where the distinction matters --
    // if you ever create a limited "support admin" role without
    // role:manage, this endpoint correctly locks them out even though
    // they pass a generic "is admin" check elsewhere.
    @PostMapping("/users/{userId}/roles")
    @PreAuthorize("hasAuthority('role:manage')")
    public ResponseEntity<Void> assignRole(
            @PathVariable UUID userId,
            @Valid @RequestBody AssignRoleRequest request
    ) {
        adminService.assignRole(userId, request.getRoleName());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/permissions")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> createPermission(@Valid @RequestBody CreatePermissionRequest request) {
        adminService.createPermission(request.getName());
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/roles/{roleId}/permissions")
    @PreAuthorize("hasAuthority('role:manage')")
    public ResponseEntity<Void> assignPermission(
            @PathVariable UUID roleId,
            @Valid @RequestBody AssignPermissionRequest request
    ) {
        adminService.assignPermissionToRole(roleId, request.getPermissionName());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/users/{userId}/deleteRole")
    @PreAuthorize("hasAuthority('role:manage')")
    public ResponseEntity<?> deleteRole(@PathVariable UUID userId, @Valid @RequestBody AssignRoleRequest request) {
        boolean roleDeleted = adminService.deleteRole(userId, request.getRoleName());
        if (roleDeleted)
            return ResponseEntity.ok(ApiResponse.success("Role deleted successfully"));
        else
            return ResponseEntity.badRequest().body(ApiResponse.error("Failed to delete role", 400));
    }
}
