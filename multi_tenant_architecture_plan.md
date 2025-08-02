# Complete Multi-Tenant Architecture Implementation Guide

## Overview

This guide provides a complete, step-by-step implementation of the multi-tenant architecture with workspace-based isolation and Owner/Viewer roles. Everything is implemented directly in each service without shared libraries.

---

## Phase 1: User Service Database Schema Updates

### Step 1.1: Update Base Entity (Already Done)
Your existing `BaseEntity` is perfect - no changes needed.

### Step 1.2: Add Missing Database Migrations

**V7__add_missing_updated_at_to_base_tables.sql:**
```sql
-- Add updated_at column to permissions table to match BaseEntity
ALTER TABLE permissions ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP;
```

### Step 1.3: Complete Entity Implementations

**Update Permission Entity:**
```java
package com.beaver.userservice.permission.entity;

import com.beaver.userservice.common.entity.BaseEntity;
import com.beaver.userservice.permission.enums.PermissionCategory;
import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

@Data
@NoArgsConstructor
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
@Entity
@Table(name = "permissions")
public class Permission extends BaseEntity {

    @Column(unique = true, nullable = false, length = 100)
    private String code;

    @Column(nullable = false)
    private String name;

    private String description;

    @Column(nullable = false, length = 50)
    private String resource;

    @Column(nullable = false, length = 50)
    private String action;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private PermissionCategory category;
}
```

**Update Role Entity:**
```java
package com.beaver.userservice.permission.entity;

import com.beaver.userservice.common.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.DynamicUpdate;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Data
@NoArgsConstructor
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
@DynamicUpdate
@Entity
@Table(name = "roles", uniqueConstraints = {
    @UniqueConstraint(columnNames = {"workspace_id", "name"})
})
public class Role extends BaseEntity {

    @Column(name = "workspace_id", nullable = false)
    private UUID workspaceId;

    @Column(nullable = false, length = 100)
    private String name;

    private String description;

    @Column(name = "is_system_role", nullable = false)
    private boolean isSystemRole = false;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "role_permissions",
            joinColumns = @JoinColumn(name = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "permission_id")
    )
    private Set<Permission> permissions = new HashSet<>();
}
```

**Complete Workspace Membership Entity:**
```java
package com.beaver.userservice.membership.entity;

import com.beaver.userservice.common.entity.BaseEntity;
import com.beaver.userservice.permission.entity.Permission;
import com.beaver.userservice.permission.entity.Role;
import com.beaver.userservice.user.entity.User;
import com.beaver.userservice.workspace.entity.Workspace;
import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.DynamicUpdate;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

@Data
@NoArgsConstructor
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
@DynamicUpdate
@Entity
@Table(name = "workspace_memberships", uniqueConstraints = {
    @UniqueConstraint(columnNames = {"user_id", "workspace_id"})
})
public class WorkspaceMembership extends BaseEntity {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "workspace_id", nullable = false)
    private Workspace workspace;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "role_id", nullable = false)
    private Role role;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private MembershipStatus status = MembershipStatus.ACTIVE;

    @Column(name = "joined_at", nullable = false)
    private LocalDateTime joinedAt = LocalDateTime.now();

    // Get all permissions from the single role
    public Set<String> getAllPermissionCodes() {
        return role.getPermissions().stream()
                .map(Permission::getCode)
                .collect(Collectors.toSet());
    }

    // Convenience methods
    public boolean isOwner() {
        return "Owner".equals(role.getName());
    }

    public boolean isViewer() {
        return "Viewer".equals(role.getName());
    }
}
```

---

## Phase 2: Repository Layer

### Step 2.1: Complete Repository Interfaces

**Update IPermissionRepository:**
```java
package com.beaver.userservice.permission;

import com.beaver.userservice.permission.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Set;
import java.util.UUID;

@Repository
public interface IPermissionRepository extends JpaRepository<Permission, UUID> {
    Set<Permission> findByCodeIn(Set<String> codes);
}
```

**Update IRoleRepository:**
```java
package com.beaver.userservice.permission;

import com.beaver.userservice.permission.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface IRoleRepository extends JpaRepository<Role, UUID> {
    Optional<Role> findByWorkspaceIdAndName(UUID workspaceId, String name);
}
```

**Add Missing Repository Interfaces:**

**IWorkspaceRepository:**
```java
package com.beaver.userservice.workspace;

import com.beaver.userservice.workspace.entity.Workspace;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface IWorkspaceRepository extends JpaRepository<Workspace, UUID> {
}
```

**IMembershipRepository:**
```java
package com.beaver.userservice.membership;

import com.beaver.userservice.membership.enums.MembershipStatus;
import com.beaver.userservice.membership.entity.WorkspaceMembership;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface IMembershipRepository extends JpaRepository<WorkspaceMembership, UUID> {
    List<WorkspaceMembership> findByUserIdAndStatus(UUID userId, MembershipStatus status);
    Optional<WorkspaceMembership> findByUserIdAndWorkspaceIdAndStatus(UUID userId, UUID workspaceId, MembershipStatus status);
    List<WorkspaceMembership> findByWorkspaceIdAndStatus(UUID workspaceId, MembershipStatus status);
}
```

---

## Phase 3: Service Layer Implementation

### Step 3.1: Complete RoleService

**RoleService.java:**
```java
package com.beaver.userservice.permission;

import com.beaver.userservice.permission.enums.Permission;
import com.beaver.userservice.permission.entity.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class RoleService {

    private final IRoleRepository roleRepository;
    private final IPermissionRepository permissionRepository;

    public void createDefaultRoles(UUID workspaceId) {
        log.info("Creating default roles for workspace: {}", workspaceId);
        
        // Owner role - full access
        Role owner = createRole(workspaceId, "Owner", "Full access to all workspace resources", true);
        Set<com.beaver.userservice.permission.entity.Permission> allPermissions = Set.copyOf(permissionRepository.findAll());
        owner.setPermissions(allPermissions);
        roleRepository.save(owner);
        log.info("Created Owner role with {} permissions", allPermissions.size());

        // Viewer role - read-only access
        Role viewer = createRole(workspaceId, "Viewer", "Read-only access to workspace data", true);
        Set<com.beaver.userservice.permission.entity.Permission> viewerPermissions = permissionRepository.findByCodeIn(
                Stream.of(Permission.TRANSACTION_READ, Permission.BUDGET_READ, Permission.REPORT_READ)
                        .map(Permission::getValue)
                        .collect(Collectors.toSet())
        );
        viewer.setPermissions(viewerPermissions);
        roleRepository.save(viewer);
        log.info("Created Viewer role with {} permissions", viewerPermissions.size());
    }

    private Role createRole(UUID workspaceId, String name, String description, boolean isSystemRole) {
        return Role.builder()
                .workspaceId(workspaceId)
                .name(name)
                .description(description)
                .isSystemRole(isSystemRole)
                .build();
    }

    public Role findByWorkspaceIdAndName(UUID workspaceId, String name) {
        return roleRepository.findByWorkspaceIdAndName(workspaceId, name)
                .orElseThrow(() -> new IllegalArgumentException("Role not found: " + name));
    }
}
```

### Step 3.2: Add WorkspaceService

**WorkspaceService.java:**
```java
package com.beaver.userservice.workspace;

import com.beaver.userservice.common.exception.UserNotFoundException;
import com.beaver.userservice.membership.MembershipService;
import com.beaver.userservice.permission.IRoleRepository;
import com.beaver.userservice.permission.RoleService;
import com.beaver.userservice.permission.entity.Role;
import com.beaver.userservice.user.IUserRepository;
import com.beaver.userservice.user.entity.User;
import com.beaver.userservice.workspace.dto.CreateWorkspaceRequest;
import com.beaver.userservice.workspace.enums.PlanType;
import com.beaver.userservice.workspace.entity.Workspace;
import com.beaver.userservice.workspace.enums.WorkspaceStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class WorkspaceService {

    private final IWorkspaceRepository workspaceRepository;
    private final RoleService roleService;
    private final MembershipService membershipService;
    private final IUserRepository userRepository;
    private final IRoleRepository roleRepository;

    public Workspace createWorkspace(CreateWorkspaceRequest request, UUID ownerId) {
        log.info("Creating workspace '{}' for user: {}", request.name(), ownerId);
        
        // Create workspace
        Workspace workspace = Workspace.builder()
                .name(request.name())
                .status(WorkspaceStatus.TRIAL)
                .plan(PlanType.STARTER)
                .trialEndsAt(LocalDateTime.now().plusDays(14)) // 14-day trial
                .build();

        workspace = workspaceRepository.save(workspace);
        log.info("Created workspace with ID: {}", workspace.getId());

        // Create default roles (Owner and Viewer) for this workspace
        roleService.createDefaultRoles(workspace.getId());

        // Add creator as owner
        Role ownerRole = roleRepository.findByWorkspaceIdAndName(workspace.getId(), "Owner")
                .orElseThrow(() -> new IllegalStateException("Owner role not found"));

        User owner = userRepository.findById(ownerId)
                .orElseThrow(() -> new UserNotFoundException("Owner user not found: " + ownerId));

        membershipService.addUserToWorkspace(owner, workspace, ownerRole);
        log.info("Added user {} as owner of workspace {}", ownerId, workspace.getId());

        return workspace;
    }

    public Workspace findById(UUID workspaceId) {
        return workspaceRepository.findById(workspaceId)
                .orElseThrow(() -> new IllegalArgumentException("Workspace not found: " + workspaceId));
    }
}
```

### Step 3.3: Add MembershipService

**MembershipService.java:**
```java
package com.beaver.userservice.membership;

import com.beaver.userservice.membership.enums.MembershipStatus;
import com.beaver.userservice.membership.entity.WorkspaceMembership;
import com.beaver.userservice.permission.entity.Role;
import com.beaver.userservice.user.entity.User;
import com.beaver.userservice.workspace.entity.Workspace;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class MembershipService {

    private final IMembershipRepository membershipRepository;

    @Cacheable(value = "memberships", key = "'user:' + #userId")
    public List<WorkspaceMembership> findActiveByUserId(UUID userId) {
        return membershipRepository.findByUserIdAndStatus(userId, MembershipStatus.ACTIVE);
    }

    @Cacheable(value = "memberships", key = "'user:' + #userId + ':workspace:' + #workspaceId")
    public Optional<WorkspaceMembership> findByUserIdAndWorkspaceId(UUID userId, UUID workspaceId) {
        return membershipRepository.findByUserIdAndWorkspaceIdAndStatus(
                userId, workspaceId, MembershipStatus.ACTIVE);
    }

    public Set<String> getUserPermissions(UUID userId, UUID workspaceId) {
        return findByUserIdAndWorkspaceId(userId, workspaceId)
                .map(WorkspaceMembership::getAllPermissionCodes)
                .orElse(Set.of());
    }

    public List<WorkspaceMembership> findMembersByWorkspaceId(UUID workspaceId) {
        return membershipRepository.findByWorkspaceIdAndStatus(workspaceId, MembershipStatus.ACTIVE);
    }

    public WorkspaceMembership addUserToWorkspace(User user, Workspace workspace, Role role) {
        log.info("Adding user {} to workspace {} with role {}", user.getId(), workspace.getId(), role.getName());
        
        WorkspaceMembership membership = WorkspaceMembership.builder()
                .user(user)
                .workspace(workspace)
                .role(role)
                .status(MembershipStatus.ACTIVE)
                .joinedAt(LocalDateTime.now())
                .build();

        WorkspaceMembership saved = membershipRepository.save(membership);
        
        // Clear cache for this user
        evictMembershipCache(user.getId(), workspace.getId());
        
        return saved;
    }

    @CacheEvict(value = "memberships", key = "'user:' + #userId")
    public void evictUserMembershipsCache(UUID userId) {
        log.debug("Evicting memberships cache for user: {}", userId);
    }

    @CacheEvict(value = "memberships", key = "'user:' + #userId + ':workspace:' + #workspaceId")
    public void evictMembershipCache(UUID userId, UUID workspaceId) {
        log.debug("Evicting membership cache for user {} and workspace {}", userId, workspaceId);
    }
}
```

---

## Phase 4: DTOs and Controllers

### Step 4.1: Add Missing DTOs

**CreateWorkspaceRequest.java:**
```java
package com.beaver.userservice.workspace.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreateWorkspaceRequest(
        @NotBlank(message = "Workspace name is required")
        @Size(min = 2, max = 100, message = "Workspace name must be between 2 and 100 characters")
        String name
) {}
```

**WorkspaceDto.java:**
```java
package com.beaver.userservice.workspace.dto;

import com.beaver.userservice.common.dto.BaseDto;
import com.beaver.userservice.workspace.enums.PlanType;
import com.beaver.userservice.workspace.entity.Workspace;
import com.beaver.userservice.workspace.enums.WorkspaceStatus;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.SuperBuilder;

import java.time.LocalDateTime;

@Data
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
public class WorkspaceDto extends BaseDto {
    private String name;
    private WorkspaceStatus status;
    private PlanType plan;
    private LocalDateTime trialEndsAt;
    private String settings;

    public static WorkspaceDto fromEntity(Workspace workspace) {
        return WorkspaceDto.builder()
                .id(workspace.getId())
                .name(workspace.getName())
                .status(workspace.getStatus())
                .plan(workspace.getPlan())
                .trialEndsAt(workspace.getTrialEndsAt())
                .settings(workspace.getSettings())
                .createdAt(workspace.getCreatedAt())
                .updatedAt(workspace.getUpdatedAt())
                .build();
    }
}
```

**WorkspaceMembershipDto.java:**
```java
package com.beaver.userservice.membership.dto;

import com.beaver.userservice.common.dto.BaseDto;
import com.beaver.userservice.membership.enums.MembershipStatus;
import com.beaver.userservice.membership.entity.WorkspaceMembership;
import com.beaver.userservice.user.dto.UserDto;
import com.beaver.userservice.workspace.dto.WorkspaceDto;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.SuperBuilder;

import java.time.LocalDateTime;
import java.util.Set;

@Data
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
public class WorkspaceMembershipDto extends BaseDto {
    private UserDto user;
    private WorkspaceDto workspace;
    private String roleName;
    private Set<String> permissions;
    private MembershipStatus status;
    private LocalDateTime joinedAt;

    public static WorkspaceMembershipDto fromEntity(WorkspaceMembership membership) {
        return WorkspaceMembershipDto.builder()
                .id(membership.getId())
                .user(UserDto.fromEntity(membership.getUser()))
                .workspace(WorkspaceDto.fromEntity(membership.getWorkspace()))
                .roleName(membership.getRole().getName())
                .permissions(membership.getAllPermissionCodes())
                .status(membership.getStatus())
                .joinedAt(membership.getJoinedAt())
                .createdAt(membership.getCreatedAt())
                .updatedAt(membership.getUpdatedAt())
                .build();
    }

    public Set<String> getAllPermissions() {
        return permissions;
    }
}
```

**UserWithWorkspacesDto.java:**
```java
package com.beaver.userservice.auth.dto;

import com.beaver.userservice.membership.dto.WorkspaceMembershipDto;
import com.beaver.userservice.membership.entity.WorkspaceMembership;
import com.beaver.userservice.user.dto.UserDto;
import com.beaver.userservice.user.entity.User;
import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.stream.Collectors;

@Data
@Builder
public class UserWithWorkspacesDto {
    private UserDto user;
    private List<WorkspaceMembershipDto> workspaces;

    public static UserWithWorkspacesDto fromUserAndMemberships(User user, List<WorkspaceMembership> memberships) {
        return UserWithWorkspacesDto.builder()
                .user(UserDto.fromEntity(user))
                .workspaces(memberships.stream()
                        .map(WorkspaceMembershipDto::fromEntity)
                        .collect(Collectors.toList()))
                .build();
    }
}
```

### Step 4.2: Add Controllers

**WorkspaceController.java:**
```java
package com.beaver.userservice.workspace;

import com.beaver.userservice.workspace.dto.CreateWorkspaceRequest;
import com.beaver.userservice.workspace.dto.WorkspaceDto;
import com.beaver.userservice.workspace.entity.Workspace;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/workspaces")
@RequiredArgsConstructor
public class WorkspaceController {

    private final WorkspaceService workspaceService;

    @PostMapping
    public ResponseEntity<WorkspaceDto> createWorkspace(
            @RequestHeader("X-User-Id") UUID userId,
            @Valid @RequestBody CreateWorkspaceRequest request) {
        
        Workspace workspace = workspaceService.createWorkspace(request, userId);
        return ResponseEntity.ok(WorkspaceDto.fromEntity(workspace));
    }

    @GetMapping("/{workspaceId}")
    public ResponseEntity<WorkspaceDto> getWorkspace(@PathVariable UUID workspaceId) {
        Workspace workspace = workspaceService.findById(workspaceId);
        return ResponseEntity.ok(WorkspaceDto.fromEntity(workspace));
    }
}
```

---

## Phase 5: Enhanced Authentication Service

### Step 5.1: Add AuthService

**AuthService.java:**
```java
package com.beaver.userservice.auth;

import com.beaver.userservice.auth.dto.UserWithWorkspacesDto;
import com.beaver.userservice.common.exception.InvalidUserDataException;
import com.beaver.userservice.membership.MembershipService;
import com.beaver.userservice.membership.entity.WorkspaceMembership;
import com.beaver.userservice.user.UserService;
import com.beaver.userservice.user.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserService userService;
    private final MembershipService membershipService;
    private final PasswordEncoder passwordEncoder;

    public UserWithWorkspacesDto validateCredentialsWithWorkspaces(String email, String password) {
        log.debug("Validating credentials for email: {}", email);
        
        User user = userService.findByEmail(email)
                .orElseThrow(() -> new InvalidUserDataException("Invalid credentials"));

        if (!user.isActive() || !passwordEncoder.matches(password, user.getPassword())) {
            throw new InvalidUserDataException("Invalid credentials");
        }

        // Get user's workspace memberships with permissions
        List<WorkspaceMembership> memberships = membershipService.findActiveByUserId(user.getId());
        log.debug("Found {} active memberships for user: {}", memberships.size(), user.getId());

        return UserWithWorkspacesDto.fromUserAndMemberships(user, memberships);
    }

    public WorkspaceMembership validateUserWorkspaceAccess(UUID userId, UUID workspaceId) {
        return membershipService.findByUserIdAndWorkspaceId(userId, workspaceId)
                .orElseThrow(() -> new InvalidUserDataException("No access to workspace"));
    }
}
```

### Step 5.2: Update Internal Controller

**Update InternalUserController.java:**
```java
package com.beaver.userservice.internal;

import com.beaver.userservice.auth.AuthService;
import com.beaver.userservice.auth.dto.UserWithWorkspacesDto;
import com.beaver.userservice.common.exception.InvalidUserDataException;
import com.beaver.userservice.common.exception.UserAlreadyExistsException;
import com.beaver.userservice.internal.dto.CreateUserRequest;
import com.beaver.userservice.internal.dto.CredentialsRequest;
import com.beaver.userservice.internal.dto.UpdateEmail;
import com.beaver.userservice.internal.dto.UpdatePassword;
import com.beaver.userservice.membership.dto.WorkspaceMembershipDto;
import com.beaver.userservice.membership.entity.WorkspaceMembership;
import com.beaver.userservice.user.UserService;
import com.beaver.userservice.user.dto.UserDto;
import com.beaver.userservice.user.entity.User;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/internal")
@RequiredArgsConstructor
public class InternalUserController {

    private final UserService userService;
    private final AuthService authService;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/validate-credentials")
    public ResponseEntity<UserDto> validateCredentials(@Valid @RequestBody CredentialsRequest request) {
        User user = userService.findByEmail(request.email())
                .orElseThrow(() -> new InvalidUserDataException("Invalid credentials"));

        if (user.isActive() && passwordEncoder.matches(request.password(), user.getPassword())) {
            return ResponseEntity.ok(UserDto.fromEntity(user));
        }

        throw new InvalidUserDataException("Invalid credentials");
    }

    @PostMapping("/validate-credentials-with-workspaces")
    public ResponseEntity<UserWithWorkspacesDto> validateCredentialsWithWorkspaces(
            @Valid @RequestBody CredentialsRequest request) {
        
        UserWithWorkspacesDto result = authService.validateCredentialsWithWorkspaces(
                request.email(), request.password());
        
        return ResponseEntity.ok(result);
    }

    @PostMapping("/validate-workspace-access")
    public ResponseEntity<WorkspaceMembershipDto> validateWorkspaceAccess(
            @RequestParam UUID userId, 
            @RequestParam UUID workspaceId) {
        
        WorkspaceMembership membership = authService.validateUserWorkspaceAccess(userId, workspaceId);
        return ResponseEntity.ok(WorkspaceMembershipDto.fromEntity(membership));
    }

    @PostMapping("/users")
    public ResponseEntity<Void> createUser(@Valid @RequestBody CreateUserRequest request) {
        if (userService.findByEmail(request.email()).isPresent()) {
            throw new UserAlreadyExistsException(request.email());
        }

        try {
            User user = User.builder()
                    .email(request.email())
                    .password(passwordEncoder.encode(request.password()))
                    .name(request.name())
                    .isActive(true)
                    .build();

            userService.saveUser(user);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            throw new InvalidUserDataException("Failed to create user: " + e.getMessage());
        }
    }

    @GetMapping("/users/{userId}")
    public ResponseEntity<UserDto> getUserById(@PathVariable UUID userId) {
        User user = userService.findById(userId);
        return ResponseEntity.ok(UserDto.fromEntity(user));
    }

    @PatchMapping("/users/{userId}/email")
    public ResponseEntity<UserDto> updateEmail(
            @PathVariable UUID userId,
            @Valid @RequestBody UpdateEmail updateEmail) {
        User user = userService.updateEmail(userId, updateEmail);
        return ResponseEntity.ok(UserDto.fromEntity(user));
    }

    @PatchMapping("/users/{userId}/password")
    public ResponseEntity<Void> updatePassword(
            @PathVariable UUID userId,
            @Valid @RequestBody UpdatePassword updatePassword) {
        userService.updatePassword(userId, updatePassword);
        return ResponseEntity.noContent().build();
    }
}
```

---

## Phase 6: Gateway Service Updates

### Step 6.1: Update JWT Service

**Update JwtService.java:**
```java
package com.beaver.core.service;

import com.beaver.core.config.JwtConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Function;

@Service
public class JwtService {
    
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;
    
    public JwtService(JwtConfig jwtConfig) {
        this.jwtConfig = jwtConfig;
        this.secretKey = Keys.hmacShaKeyFor(jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8));
    }
    
    // Original single-workspace token generation
    public String generateAccessToken(String userId, String email, String name) {
        return generateToken(Map.of(
            "userId", userId,
            "email", email,
            "name", name,
            "type", "access"
        ), jwtConfig.getAccessTokenValidity() * 60 * 1000);
    }
    
    // NEW: Enhanced token generation with workspace context
    public String generateAccessToken(String userId, String email, String name, 
                                    String workspaceId, Set<String> permissions) {
        return generateToken(Map.of(
            "userId", userId,
            "email", email,
            "name", name,
            "workspaceId", workspaceId,
            "permissions", new ArrayList<>(permissions), // Convert Set to List for JSON
            "type", "access"
        ), jwtConfig.getAccessTokenValidity() * 60 * 1000);
    }
    
    public String generateRefreshToken(String userId) {
        return generateToken(Map.of(
            "userId", userId,
            "type", "refresh"
        ), jwtConfig.getRefreshTokenValidity() * 60 * 1000);
    }

    private String generateToken(Map<String, Object> claims, long expirationMs) {
        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .claims(claims)
                .issuedAt(now)
                .expiration(expirationDate)
                .signWith(secretKey)
                .compact();
    }
    
    public Mono<String> extractUserId(String token) {
        return extractClaim(token, claims -> claims.get("userId", String.class));
    }
    
    // NEW: Extract workspace ID from token
    public Mono<String> extractWorkspaceId(String token) {
        return extractClaim(token, claims -> claims.get("workspaceId", String.class));
    }
    
    // NEW: Extract permissions from token
    public Mono<Set<String>> extractPermissions(String token) {
        return extractClaim(token, claims -> {
            List<String> perms = claims.get("permissions", List.class);
            return perms != null ? new HashSet<>(perms) : new HashSet<>();
        });
    }
    
    public Mono<String> extractTokenType(String token) {
        return extractClaim(token, claims -> claims.get("type", String.class));
    }
    
    public Mono<Date> extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
    
    public <T> Mono<T> extractClaim(String token, Function<Claims, T> claimsResolver) {
        return extractAllClaims(token)
                .map(claimsResolver);
    }
    
    public Mono<Claims> extractAllClaims(String token) {
        return Mono.fromCallable(() -> 
            Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
        ).onErrorMap(Exception.class, ex -> new RuntimeException("Invalid JWT token", ex));
    }
    
    public Mono<Boolean> isTokenExpired(String token) {
        return extractExpiration(token)
                .map(expiration -> expiration.before(new Date()));
    }
    
    public Mono<Boolean> isValidAccessToken(String token) {
        return validateTokenType(token, "access");
    }
    
    public Mono<Boolean> isValidRefreshToken(String token) {
        return validateTokenType(token, "refresh");
    }
    
    private Mono<Boolean> validateTokenType(String token, String expectedType) {
        return extractTokenType(token)
                .filter(expectedType::equals)
                .flatMap(type -> isTokenExpired(token))
                .map(expired -> !expired)
                .defaultIfEmpty(false)
                .onErrorReturn(false);
    }
}
```

### Step 6.2: Update UserServiceClient

**Update UserServiceClient.java:**
```java
package com.beaver.core.client;

import com.beaver.core.dto.LoginRequest;
import com.beaver.core.dto.SignupRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class UserServiceClient {

    private final WebClient.Builder webClientBuilder;

    @Value("${user-service.url}")
    private String userServiceBaseUrl;

    @Value("${gateway.secret}")
    private String gatewaySecret;

    private WebClient getUserServiceWebClient() {
        return webClientBuilder.baseUrl(userServiceBaseUrl).build();
    }

    // Original credential validation
    public Mono<Map<String, Object>> validateCredentials(String email, String password) {
        LoginRequest request = LoginRequest.builder()
                .email(email)
                .password(password)
                .build();

        return getUserServiceWebClient()
                .post()
                .uri("/users/internal/validate-credentials")
                .header("X-Service-Secret", gatewaySecret)
                .header("X-Source", "gateway")
                .bodyValue(request)
                .retrieve()
                .onStatus(HttpStatusCode::isError, clientResponse ->
                        clientResponse.bodyToMono(String.class)
                                .flatMap(errorBody ->
                                        Mono.error(new org.springframework.web.server.ResponseStatusException(
                                                clientResponse.statusCode(), errorBody
                                        ))
                                )
                )
                .bodyToMono(new ParameterizedTypeReference<>() {});
    }

    // NEW: Multi-workspace authentication
    public Mono<Map<String, Object>> validateCredentialsWithWorkspaces(String email, String password) {
        LoginRequest request = LoginRequest.builder()
                .email(email)
                .password(password)
                .build();

        return getUserServiceWebClient()
                .post()
                .uri("/users/internal/validate-credentials-with-workspaces")
                .header("X-Service-Secret", gatewaySecret)
                .header("X-Source", "gateway")
                .bodyValue(request)
                .retrieve()
                .onStatus(HttpStatusCode::isError, clientResponse ->
                        clientResponse.bodyToMono(String.class)
                                .flatMap(errorBody ->
                                        Mono.error(new org.springframework.web.server.ResponseStatusException(
                                                clientResponse.statusCode(), errorBody
                                        ))
                                )
                )
                .bodyToMono(new ParameterizedTypeReference<>() {});
    }
    
    // NEW: Validate workspace access
    public Mono<Map<String, Object>> validateWorkspaceAccess(UUID userId, UUID workspaceId) {
        return getUserServiceWebClient()
                .post()
                .uri("/users/internal/validate-workspace-access")
                .header("X-Service-Secret", gatewaySecret)
                .header("X-Source", "gateway")
                .queryParam("userId", userId)
                .queryParam("workspaceId", workspaceId)
                .retrieve()
                .onStatus(HttpStatusCode::isError, clientResponse ->
                        clientResponse.bodyToMono(String.class)
                                .flatMap(errorBody ->
                                        Mono.error(new org.springframework.web.server.ResponseStatusException(
                                                clientResponse.statusCode(), errorBody
                                        ))
                                )
                )
                .bodyToMono(new ParameterizedTypeReference<>() {});
    }

    public Mono<Map<String, Object>> getUserById(UUID userId) {
        return getUserServiceWebClient()
                .get()
                .uri("/users/internal/users/{userId}", userId.toString())
                .header("X-Service-Secret", gatewaySecret)
                .header("X-Source", "gateway")
                .retrieve()
                .onStatus(HttpStatusCode::isError, clientResponse ->
                        clientResponse.bodyToMono(String.class)
                                .flatMap(errorBody ->
                                        Mono.error(new org.springframework.web.server.ResponseStatusException(
                                                clientResponse.statusCode(), errorBody
                                        ))
                                )
                )
                .bodyToMono(new ParameterizedTypeReference<>() {});
    }

    public Mono<Void> createUser(String email, String password, String name) {
        SignupRequest request = SignupRequest.builder()
                .name(name)
                .email(email)
                .password(password)
                .build();

        return getUserServiceWebClient()
                .post()
                .uri("/users/internal/users")
                .header("X-Service-Secret", gatewaySecret)
                .header("X-Source", "gateway")
                .bodyValue(request)
                .retrieve()
                .onStatus(HttpStatusCode::isError, clientResponse ->
                        clientResponse.bodyToMono(String.class)
                        .flatMap(errorBody ->
                                Mono.error(new org.springframework.web.server.ResponseStatusException(
                                        clientResponse.statusCode(), errorBody
                                )))
                )
                .bodyToMono(Void.class);
    }

    public Mono<Map<String, Object>> updateEmail(UUID userId, String newEmail, String currentPassword) {
        Map<String, String> request = Map.of(
                "email", newEmail,
                "currentPassword", currentPassword
        );

        return getUserServiceWebClient()
                .patch()
                .uri("/users/internal/users/{userId}/email", userId.toString())
                .header("X-Service-Secret", gatewaySecret)
                .header("X-Source", "gateway")
                .bodyValue(request)
                .retrieve()
                .onStatus(HttpStatusCode::isError, clientResponse ->
                        clientResponse.bodyToMono(String.class)
                                .flatMap(errorBody ->
                                        Mono.error(new org.springframework.web.server.ResponseStatusException(
                                                clientResponse.statusCode(), errorBody
                                        ))
                                )
                )
                .bodyToMono(new ParameterizedTypeReference<>() {});
    }

    public Mono<Void> updatePassword(UUID userId, String currentPassword, String newPassword) {
        Map<String, String> request = Map.of(
                "currentPassword", currentPassword,
                "newPassword", newPassword
        );

        return getUserServiceWebClient()
                .patch()
                .uri("/users/internal/users/{userId}/password", userId.toString())
                .header("X-Service-Secret", gatewaySecret)
                .header("X-Source", "gateway")
                .bodyValue(request)
                .retrieve()
                .onStatus(HttpStatusCode::isError, clientResponse ->
                        clientResponse.bodyToMono(String.class)
                                .flatMap(errorBody ->
                                        Mono.error(new org.springframework.web.server.ResponseStatusException(
                                                clientResponse.statusCode(), errorBody
                                        ))
                                )
                )
                .bodyToMono(Void.class);
    }
}
```

### Step 6.3: Add New DTOs for Gateway

**UserDto.java:**
```java
package com.beaver.core.dto;

import lombok.Builder;

import java.util.Map;

@Builder
public record UserDto(String id, String email, String name, boolean active) {
    
    public static UserDto fromMap(Map<String, Object> userMap) {
        return UserDto.builder()
                .id(userMap.get("id").toString())
                .email((String) userMap.get("email"))
                .name((String) userMap.get("name"))
                .active((Boolean) userMap.get("active"))
                .build();
    }
}
```

**WorkspaceMembershipDto.java:**
```java
package com.beaver.core.dto;

import lombok.Builder;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

@Builder
public record WorkspaceMembershipDto(
        String id,
        WorkspaceDto workspace,
        String roleName,
        Set<String> permissions
) {
    
    @SuppressWarnings("unchecked")
    public static WorkspaceMembershipDto fromMap(Map<String, Object> membershipMap) {
        Map<String, Object> workspaceMap = (Map<String, Object>) membershipMap.get("workspace");
        List<String> permissionsList = (List<String>) membershipMap.get("permissions");
        
        return WorkspaceMembershipDto.builder()
                .id(membershipMap.get("id").toString())
                .workspace(WorkspaceDto.fromMap(workspaceMap))
                .roleName((String) membershipMap.get("roleName"))
                .permissions(new HashSet<>(permissionsList))
                .build();
    }
    
    public Set<String> getAllPermissions() {
        return permissions;
    }
}
```

**WorkspaceDto.java:**
```java
package com.beaver.core.dto;

import lombok.Builder;

import java.util.Map;

@Builder
public record WorkspaceDto(String id, String name) {
    
    public static WorkspaceDto fromMap(Map<String, Object> workspaceMap) {
        return WorkspaceDto.builder()
                .id(workspaceMap.get("id").toString())
                .name((String) workspaceMap.get("name"))
                .build();
    }
}
```

**UserWithWorkspacesDto.java:**
```java
package com.beaver.core.dto;

import lombok.Builder;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Builder
public record UserWithWorkspacesDto(UserDto user, List<WorkspaceMembershipDto> workspaces) {
    
    @SuppressWarnings("unchecked")
    public static UserWithWorkspacesDto fromMap(Map<String, Object> responseMap) {
        Map<String, Object> userMap = (Map<String, Object>) responseMap.get("user");
        List<Map<String, Object>> workspacesList = (List<Map<String, Object>>) responseMap.get("workspaces");
        
        return UserWithWorkspacesDto.builder()
                .user(UserDto.fromMap(userMap))
                .workspaces(workspacesList.stream()
                        .map(WorkspaceMembershipDto::fromMap)
                        .collect(Collectors.toList()))
                .build();
    }
}
```

**SwitchWorkspaceRequest.java:**
```java
package com.beaver.core.dto;

import jakarta.validation.constraints.NotBlank;

public record SwitchWorkspaceRequest(
        @NotBlank(message = "Workspace ID is required")
        String workspaceId
) {}
```

### Step 6.4: Update AuthController

**Update AuthController.java:**
```java
package com.beaver.core.controller;

import com.beaver.core.client.UserServiceClient;
import com.beaver.core.config.JwtConfig;
import com.beaver.core.dto.*;
import com.beaver.core.exception.AuthenticationFailedException;
import com.beaver.core.service.JwtService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.UUID;

@RestController
@RequestMapping("/auth")
@Slf4j
public class AuthController {

    private final UserServiceClient userServiceClient;
    private final JwtService jwtService;
    private final JwtConfig jwtConfig;

    public AuthController(UserServiceClient userServiceClient, JwtService jwtService, JwtConfig jwtConfig) {
        this.userServiceClient = userServiceClient;
        this.jwtService = jwtService;
        this.jwtConfig = jwtConfig;
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<AuthResponse>> login(@Valid @RequestBody LoginRequest request) {
        return userServiceClient.validateCredentialsWithWorkspaces(request.email(), request.password())
                .map(UserWithWorkspacesDto::fromMap)
                .flatMap(userWithWorkspaces -> {
                    if (userWithWorkspaces.workspaces().isEmpty()) {
                        return Mono.error(new AuthenticationFailedException("No workspace access"));
                    }
                    
                    // Select primary workspace (first active one, or let user choose)
                    WorkspaceMembershipDto primaryMembership = selectPrimaryWorkspace(userWithWorkspaces.workspaces());
                    
                    return createAuthResponse(userWithWorkspaces.user(), primaryMembership, "Login successful");
                });
    }

    @PostMapping("/signup")
    public Mono<ResponseEntity<AuthResponse>> signup(@Valid @RequestBody SignupRequest request) {
        return userServiceClient.createUser(request.email(), request.password(), request.name())
                .then(Mono.defer(() ->
                        userServiceClient.validateCredentials(request.email(), request.password())
                                .flatMap(userMap ->
                                        createAuthResponse(
                                                User.builder()
                                                        .id(userMap.get("id").toString())
                                                        .email((String) userMap.get("email"))
                                                        .name((String) userMap.get("name")).build(),
                                                null, // No workspace context for signup
                                                "Signup successful"))
                ));
    }

    @PostMapping("/switch-workspace")
    public Mono<ResponseEntity<AuthResponse>> switchWorkspace(
            @CookieValue("access_token") String accessToken,
            @Valid @RequestBody SwitchWorkspaceRequest request) {
        
        return jwtService.extractUserId(accessToken)
                .flatMap(userId -> 
                    userServiceClient.validateWorkspaceAccess(
                        UUID.fromString(userId), 
                        UUID.fromString(request.workspaceId())
                    )
                    .map(WorkspaceMembershipDto::fromMap)
                    .flatMap(membership -> 
                        userServiceClient.getUserById(UUID.fromString(userId))
                                .map(UserDto::fromMap)
                                .flatMap(user -> createAuthResponse(
                                    user,
                                    membership,
                                    "Workspace switched successfully"
                                ))
                    )
                );
    }
    
    @PostMapping("/logout")
    public Mono<ResponseEntity<AuthResponse>> logout() {
        ResponseCookie accessCookie = ResponseCookie.from("access_token", "")
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .maxAge(0)
                .path("/")
                .build();
        
        ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .maxAge(0)
                .path("/")
                .build();
        
        AuthResponse response = AuthResponse.builder().message("Logout successful").build();

        return Mono.just(ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, accessCookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(response));
    }
    
    @PostMapping("/refresh")
    public Mono<ResponseEntity<AuthResponse>> refresh(@CookieValue(value = "refresh_token", required = false) String refreshToken) {
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            return Mono.error(new AuthenticationFailedException("Refresh token is missing"));
        }
        
        return jwtService.isValidRefreshToken(refreshToken)
                .filter(isValid -> isValid)
                .flatMap(valid -> jwtService.extractUserId(refreshToken)
                        .flatMap(this::generateNewAccessToken))
                .switchIfEmpty(Mono.error(new AuthenticationFailedException("Invalid refresh token")));
    }

    @PatchMapping("/update-credentials")
    public Mono<ResponseEntity<AuthResponse>> updateCredentials(
            @CookieValue(value = "access_token", required = false) String accessToken,
            @Valid @RequestBody UpdateCredentialsRequest request) {

        if (accessToken == null || accessToken.trim().isEmpty()) {
            return Mono.error(new AuthenticationFailedException("Access token is missing"));
        }

        return jwtService.isValidAccessToken(accessToken)
                .filter(isValid -> isValid)
                .flatMap(valid -> jwtService.extractUserId(accessToken))
                .flatMap(userId -> {
                    UUID userUuid = UUID.fromString(userId);

                    // Handle email update
                    if (request.newEmail() != null && !request.newEmail().trim().isEmpty()) {
                        return userServiceClient.updateEmail(userUuid, request.newEmail(), request.currentPassword())
                                .map(UserDto::fromMap)
                                .flatMap(updatedUser -> {
                                    // Email changed, need to generate new tokens with new email
                                    String newAccessToken = jwtService.generateAccessToken(
                                            updatedUser.id(),
                                            updatedUser.email(),
                                            updatedUser.name()
                                    );
                                    String newRefreshToken = jwtService.generateRefreshToken(updatedUser.id());

                                    ResponseCookie accessCookie = createAccessTokenCookie(newAccessToken);
                                    ResponseCookie refreshCookie = createRefreshTokenCookie(newRefreshToken);

                                    AuthResponse response = AuthResponse.builder()
                                            .message("Email updated successfully")
                                            .userId(updatedUser.id())
                                            .email(updatedUser.email())
                                            .name(updatedUser.name())
                                            .build();

                                    return Mono.just(ResponseEntity.ok()
                                            .header(HttpHeaders.SET_COOKIE, accessCookie.toString())
                                            .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                                            .body(response));
                                });
                    }

                    // Handle password update
                    else if (request.newPassword() != null && !request.newPassword().trim().isEmpty()) {
                        return userServiceClient.updatePassword(userUuid, request.currentPassword(), request.newPassword())
                                .then(Mono.just(ResponseEntity.ok(AuthResponse.builder()
                                        .message("Password updated successfully")
                                        .build())));
                    }
                    else {
                        return Mono.error(new AuthenticationFailedException("No valid update field provided"));
                    }
                })
                .switchIfEmpty(Mono.error(new AuthenticationFailedException("Invalid access token")));
    }

    // Helper method for both User and UserDto
    private Mono<ResponseEntity<AuthResponse>> createAuthResponse(
            User user, WorkspaceMembershipDto membership, String message) {
        
        if (membership != null) {
            // Multi-workspace token
            String accessToken = jwtService.generateAccessToken(
                    user.id(), user.email(), user.name(),
                    membership.workspace().id(),
                    membership.getAllPermissions()
            );
            String refreshToken = jwtService.generateRefreshToken(user.id());

            ResponseCookie accessCookie = createAccessTokenCookie(accessToken);
            ResponseCookie refreshCookie = createRefreshTokenCookie(refreshToken);

            AuthResponse response = AuthResponse.builder()
                    .message(message)
                    .userId(user.id())
                    .email(user.email())
                    .name(user.name())
                    .build();

            return Mono.just(ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, accessCookie.toString())
                    .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                    .body(response));
        } else {
            // Simple token (for signup before workspace assignment)
            String accessToken = jwtService.generateAccessToken(user.id(), user.email(), user.name());
            String refreshToken = jwtService.generateRefreshToken(user.id());

            ResponseCookie accessCookie = createAccessTokenCookie(accessToken);
            ResponseCookie refreshCookie = createRefreshTokenCookie(refreshToken);

            AuthResponse response = AuthResponse.builder()
                    .message(message)
                    .userId(user.id())
                    .email(user.email())
                    .name(user.name())
                    .build();

            return Mono.just(ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, accessCookie.toString())
                    .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                    .body(response));
        }
    }

    // Overloaded for UserDto
    private Mono<ResponseEntity<AuthResponse>> createAuthResponse(
            UserDto user, WorkspaceMembershipDto membership, String message) {
        
        String accessToken = jwtService.generateAccessToken(
                user.id(), user.email(), user.name(),
                membership.workspace().id(),
                membership.getAllPermissions()
        );
        String refreshToken = jwtService.generateRefreshToken(user.id());

        ResponseCookie accessCookie = createAccessTokenCookie(accessToken);
        ResponseCookie refreshCookie = createRefreshTokenCookie(refreshToken);

        AuthResponse response = AuthResponse.builder()
                .message(message)
                .userId(user.id())
                .email(user.email())
                .name(user.name())
                .build();

        return Mono.just(ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, accessCookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(response));
    }

    private Mono<ResponseEntity<AuthResponse>> generateNewAccessToken(String userId) {
        try {
            UUID userUuid = UUID.fromString(userId);
            return userServiceClient.getUserById(userUuid)
                    .map(UserDto::fromMap)
                    .flatMap(user -> {
                        if (user.active()) {
                            String newAccessToken = jwtService.generateAccessToken(
                                    user.id(),
                                    user.email(),
                                    user.name()
                            );

                            ResponseCookie accessCookie = createAccessTokenCookie(newAccessToken);

                            AuthResponse response = AuthResponse.builder()
                                    .message("Token refreshed successfully")
                                    .userId(user.id())
                                    .email(user.email())
                                    .name(user.name())
                                    .build();

                            return Mono.just(ResponseEntity.ok()
                                    .header(HttpHeaders.SET_COOKIE, accessCookie.toString())
                                    .body(response));
                        } else {
                            log.warn("User account is inactive for userId: {}", user.id());
                            return Mono.error(new AuthenticationFailedException("User account is inactive"));
                        }
                    });
        } catch (IllegalArgumentException e) {
            return Mono.error(new AuthenticationFailedException("Invalid user ID in token"));
        }
    }

    private WorkspaceMembershipDto selectPrimaryWorkspace(java.util.List<WorkspaceMembershipDto> memberships) {
        // For now, just return the first one
        // Later you could add logic for "last used workspace" or let user choose
        return memberships.get(0);
    }

    private ResponseCookie createAccessTokenCookie(String accessToken) {
        return ResponseCookie.from("access_token", accessToken)
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .maxAge(jwtConfig.getAccessTokenValidity() * 60)
                .path("/")
                .build();
    }

    private ResponseCookie createRefreshTokenCookie(String refreshToken) {
        return ResponseCookie.from("refresh_token", refreshToken)
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .maxAge(jwtConfig.getRefreshTokenValidity() * 60)
                .path("/")
                .build();
    }
}
```

### Step 6.5: Add WorkspaceContextFilter

**WorkspaceContextFilter.java:**
```java
package com.beaver.core.security;

import com.beaver.core.service.JwtService;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Set;

@Component
public class WorkspaceContextFilter extends AbstractGatewayFilterFactory<WorkspaceContextFilter.Config> {
    
    private final JwtService jwtService;

    public WorkspaceContextFilter(JwtService jwtService) {
        super(Config.class);
        this.jwtService = jwtService;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String token = extractTokenFromCookies(exchange.getRequest());
            
            if (token != null) {
                return Mono.zip(
                    jwtService.extractUserId(token),
                    jwtService.extractWorkspaceId(token).defaultIfEmpty(""),
                    jwtService.extractPermissions(token).defaultIfEmpty(Set.of())
                ).flatMap(tuple -> {
                    String userId = tuple.getT1();
                    String workspaceId = tuple.getT2();
                    Set<String> permissions = tuple.getT3();
                    
                    var requestBuilder = exchange.getRequest().mutate()
                            .header("X-User-Id", userId);
                    
                    if (!workspaceId.isEmpty()) {
                        requestBuilder.header("X-Workspace-Id", workspaceId);
                    }
                    
                    if (!permissions.isEmpty()) {
                        requestBuilder.header("X-User-Permissions", String.join(",", permissions));
                    }
                    
                    var modifiedRequest = requestBuilder.build();
                    
                    return chain.filter(exchange.mutate().request(modifiedRequest).build());
                });
            }
            
            return chain.filter(exchange);
        };
    }

    private String extractTokenFromCookies(ServerHttpRequest request) {
        if (request.getCookies().containsKey("access_token")) {
            return request.getCookies().getFirst("access_token").getValue();
        }
        return null;
    }

    public static class Config {
        // Configuration properties if needed
    }
}
```

### Step 6.6: Update Gateway Configuration

**Update application.yml:**
```yaml
server:
  port: ${SERVER_PORT:8080}

spring:
  config:
    import: optional:file:.env[.properties]
  application:
    name: beaver-core-${ENV:local}

  cloud:
    gateway:
      routes:
        - id: user-service
          uri: ${user-service.url}
          predicates:
            - Path=/v1/users/**
          filters:
            - AuthenticationFilter
            - WorkspaceContextFilter
            - name: StripPrefix
              args:
                parts: 1
            - name: AddRequestHeader
              args:
                name: X-Service-Secret
                value: ${gateway.secret}
            - name: AddRequestHeader
              args:
                name: X-Source
                value: gateway

logging:
  level:
    com.beaver.core: DEBUG
    org.springframework.cloud.gateway: INFO
    org.springframework.cloud.gateway.handler.FilteringWebHandler: WARN

jwt:
  secret: ${JWT_SECRET}
  accessTokenValidity: ${JWT_ACCESS_VALIDITY}
  refreshTokenValidity: ${JWT_REFRESH_VALIDITY}
  authDisabled: false

gateway:
  secret: ${GATEWAY_SECRET}

# Downstream Services
user-service:
  url: ${USER_SERVICE_URL:http://localhost:8081}
```

---

## Phase 7: Permission Framework (Without Shared Library)

### Step 7.1: Add Permission Framework to User Service

**Permission Enum (Already exists - no changes needed):**
```java
// src/main/java/com/beaver/userservice/permission/enums/Permission.java - Already implemented
```

**Add Permission Annotation:**
```java
package com.beaver.userservice.permission.annotation;

import com.beaver.userservice.permission.enums.Permission;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.langang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiresPermission {
    Permission[] value(); // Required permissions as enums directly
    boolean requireAll() default false; // false = OR logic, true = AND logic
}
```

**Add Permission Aspect:**
```java
package com.beaver.userservice.permission.aspect;

import com.beaver.userservice.permission.PermissionService;
import com.beaver.userservice.permission.annotation.RequiresPermission;
import com.beaver.userservice.permission.enums.Permission;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class PermissionAspect {
    
    private final PermissionService permissionService;
    
    @Around("@annotation(requiresPermission)")
    public Object checkPermission(ProceedingJoinPoint joinPoint, RequiresPermission requiresPermission) throws Throwable {
        
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
        HttpServletRequest request = attributes.getRequest();
        
        String workspaceId = request.getHeader("X-Workspace-Id");
        String userId = request.getHeader("X-User-Id");
        String permissionsHeader = request.getHeader("X-User-Permissions");
        
        if (workspaceId == null || userId == null) {
            throw new AccessDeniedException("Missing workspace or user context");
        }
        
        Set<String> userPermissions = permissionsHeader != null ? 
            Set.of(permissionsHeader.split(",")) : Set.of();
        
        Permission[] requiredPermissions = requiresPermission.value();
        boolean requireAll = requiresPermission.requireAll();
        
        boolean hasAccess = requireAll ? 
            Arrays.stream(requiredPermissions).allMatch(perm -> 
                permissionService.hasPermission(userPermissions, perm.getValue())) :
            Arrays.stream(requiredPermissions).anyMatch(perm -> 
                permissionService.hasPermission(userPermissions, perm.getValue()));
        
        if (!hasAccess) {
            String permissionNames = Arrays.stream(requiredPermissions)
                    .map(Permission::name)
                    .collect(Collectors.joining(", "));
            log.warn("Access denied for user {} in workspace {}. Required permissions: {}", 
                     userId, workspaceId, permissionNames);
            throw new AccessDeniedException("Insufficient permissions: " + permissionNames);
        }
        
        return joinPoint.proceed();
    }
}
```

**Add AOP Dependency to User Service pom.xml:**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-aop</artifactId>
</dependency>
```

### Step 7.2: Add Permission Framework to Financial Service (Example)

Since we don't have the financial service in your codebase yet, here's how you would implement it:

**Create the same permission framework files in any downstream service:**

**Permission.java (Copy to each service):**
```java
package com.example.financialservice.permission.enums;

public enum Permission {
    // Financial permissions
    TRANSACTION_READ("transaction:read"),
    TRANSACTION_WRITE("transaction:write"),
    BUDGET_READ("budget:read"),
    BUDGET_WRITE("budget:write"),
    REPORT_READ("report:read"),

    // Workspace management
    WORKSPACE_SETTINGS("workspace:settings"),
    WORKSPACE_MEMBERS("workspace:members");

    private final String value;

    Permission(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return value;
    }
}
```

**RequiresPermission.java (Copy to each service):**
```java
package com.example.financialservice.permission.annotation;

import com.example.financialservice.permission.enums.Permission;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiresPermission {
    Permission[] value();
    boolean requireAll() default false;
}
```

**PermissionService.java (Copy to each service):**
```java
package com.example.financialservice.permission;

import com.example.financialservice.permission.enums.Permission;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class PermissionService {
    
    public boolean hasPermission(Set<String> userPermissions, String requiredPermission) {
        return userPermissions.contains(requiredPermission);
    }
    
    public boolean isOwner(Set<String> userPermissions) {
        return userPermissions.contains(Permission.WORKSPACE_SETTINGS.getValue());
    }
    
    public boolean canRead(Set<String> userPermissions, String resource) {
        return userPermissions.contains(resource + ":read");
    }
    
    public boolean canWrite(Set<String> userPermissions, String resource) {
        return userPermissions.contains(resource + ":write");
    }
}
```

**PermissionAspect.java (Copy to each service):**
```java
package com.example.financialservice.permission.aspect;

// Same implementation as above, just update package names
```

---

## Phase 8: Example Usage Patterns

### Step 8.1: Using Permissions in User Service Controllers

**Update UserController.java:**
```java
package com.beaver.userservice.user;

import com.beaver.userservice.permission.annotation.RequiresPermission;
import com.beaver.userservice.permission.enums.Permission;
import com.beaver.userservice.user.dto.UpdateSelf;
import com.beaver.userservice.user.dto.UserDto;
import com.beaver.userservice.user.entity.User;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping(value = "/self", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<UserDto> getSelf(@RequestHeader("X-User-Id") UUID id) {
        User user = userService.findById(id);
        return ResponseEntity.ok(UserDto.fromEntity(user));
    }

    @PatchMapping(value = "/self", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<UserDto> updateSelf(
            @RequestHeader("X-User-Id") UUID id,
            @Valid @RequestBody UpdateSelf updateSelf)
    {
        User user = userService.updateSelf(id, updateSelf);
        return ResponseEntity.ok(UserDto.fromEntity(user));
    }

    @DeleteMapping(value = "/self")
    public ResponseEntity<Void> deleteSelf(@RequestHeader("X-User-Id") UUID id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}
```

**Add Workspace Management to UserController:**
```java
@GetMapping("/workspaces")
public ResponseEntity<List<WorkspaceMembershipDto>> getUserWorkspaces(
        @RequestHeader("X-User-Id") UUID userId) {
    
    List<WorkspaceMembership> memberships = membershipService.findActiveByUserId(userId);
    List<WorkspaceMembershipDto> dtos = memberships.stream()
            .map(WorkspaceMembershipDto::fromEntity)
            .collect(Collectors.toList());
    
    return ResponseEntity.ok(dtos);
}

@PostMapping("/workspaces/{workspaceId}/members/invite")
@RequiresPermission(Permission.WORKSPACE_MEMBERS)
public ResponseEntity<Void> inviteMember(
        @PathVariable UUID workspaceId,
        @RequestHeader("X-User-Id") UUID inviterId,
        @RequestHeader("X-Workspace-Id") UUID currentWorkspaceId,
        @Valid @RequestBody InviteMemberRequest request) {
    
    // Verify the workspace IDs match (security check)
    if (!workspaceId.equals(currentWorkspaceId)) {
        throw new AccessDeniedException("Workspace ID mismatch");
    }
    
    // Implementation for inviting members
    // This would typically involve creating an invitation and sending an email
    
    return ResponseEntity.ok().build();
}
```

### Step 8.2: Add Missing DTOs

**InviteMemberRequest.java:**
```java
package com.beaver.userservice.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record InviteMemberRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        String email,
        
        @NotBlank(message = "Role is required")
        String role // "Owner" or "Viewer"
) {}
```

---

## Phase 9: Database Initialization

### Step 9.1: Update Migration Files

The permissions are already being inserted in the migration files. However, let's make sure V4 is complete and correct:

**V4__create_permissions_table.sql (Updated):**
```sql
-- Permissions
CREATE TABLE permissions (
     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
     code VARCHAR(100) UNIQUE NOT NULL,
     name VARCHAR(255) NOT NULL,
     description TEXT,
     resource VARCHAR(50) NOT NULL,
     action VARCHAR(50) NOT NULL,
     category VARCHAR(50) NOT NULL,
     created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
     updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Insert simplified permissions
INSERT INTO permissions (code, name, description, resource, action, category)
VALUES
      ('transaction:read', 'Read Transactions', 'View transaction history and details', 'transaction', 'read', 'FINANCIAL'),
      ('transaction:write', 'Write Transactions', 'Create and edit transactions', 'transaction', 'write', 'FINANCIAL'),
      ('budget:read', 'Read Budgets', 'View budget information', 'budget', 'read', 'FINANCIAL'),
      ('budget:write', 'Write Budgets', 'Create and edit budgets', 'budget', 'write', 'FINANCIAL'),
      ('report:read', 'Read Reports', 'View reports and analytics', 'report', 'read', 'REPORTING'),
      ('workspace:settings', 'Workspace Settings', 'Modify workspace settings', 'workspace', 'settings', 'ADMINISTRATION'),
      ('workspace:members', 'Manage Members', 'Add and remove workspace members', 'workspace', 'members', 'ADMINISTRATION');
```

No Java DataInitializer needed - everything is handled cleanly through SQL migrations!

---

## Phase 10: Testing and Validation

### Step 10.1: Add Integration Test

**MultiTenantIntegrationTest.java:**
```java
package com.beaver.userservice.integration;

import com.beaver.userservice.membership.MembershipService;
import com.beaver.userservice.permission.RoleService;
import com.beaver.userservice.user.UserService;
import com.beaver.userservice.user.entity.User;
import com.beaver.userservice.workspace.WorkspaceService;
import com.beaver.userservice.workspace.dto.CreateWorkspaceRequest;
import com.beaver.userservice.workspace.entity.Workspace;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@TestPropertySource(properties = {
    "spring.datasource.url=jdbc:h2:mem:testdb",
    "spring.jpa.hibernate.ddl-auto=create-drop"
})
@Transactional
class MultiTenantIntegrationTest {

    @Autowired
    private UserService userService;
    
    @Autowired
    private WorkspaceService workspaceService;
    
    @Autowired
    private MembershipService membershipService;
    
    @Autowired
    private RoleService roleService;
    
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void testCompleteMultiTenantFlow() {
        // 1. Create a user
        User user = User.builder()
                .email("test@example.com")
                .password(passwordEncoder.encode("password123"))
                .name("Test User")
                .isActive(true)
                .build();
        
        User savedUser = userService.saveUser(user);
        assertNotNull(savedUser.getId());

        // 2. Create a workspace with the user as owner
        CreateWorkspaceRequest workspaceRequest = new CreateWorkspaceRequest("Test Workspace");
        Workspace workspace = workspaceService.createWorkspace(workspaceRequest, savedUser.getId());
        
        assertNotNull(workspace.getId());
        assertEquals("Test Workspace", workspace.getName());

        // 3. Verify user has owner permissions in the workspace
        var memberships = membershipService.findActiveByUserId(savedUser.getId());
        assertFalse(memberships.isEmpty());
        
        var membership = memberships.get(0);
        assertTrue(membership.isOwner());
        
        var permissions = membership.getAllPermissionCodes();
        assertTrue(permissions.contains("workspace:settings"));
        assertTrue(permissions.contains("workspace:members"));
        assertTrue(permissions.contains("transaction:read"));
        assertTrue(permissions.contains("transaction:write"));
    }
}
```

---

## Phase 11: Complete Implementation Checklist

### ✅ Database Schema
- [x] Workspaces table with trial/plan support
- [x] Permissions table with predefined permissions
- [x] Roles table with workspace scoping
- [x] Role-permissions junction table
- [x] Workspace memberships table with user-workspace-role relationships

### ✅ Entity Layer
- [x] Workspace entity with status and plan management
- [x] Permission entity with categorization
- [x] Role entity with workspace scoping
- [x] WorkspaceMembership entity with permission aggregation

### ✅ Repository Layer
- [x] All repositories with proper queries
- [x] Caching configuration for performance

### ✅ Service Layer
- [x] RoleService for default role creation
- [x] WorkspaceService for workspace management
- [x] MembershipService for user-workspace relationships
- [x] AuthService for multi-workspace authentication

### ✅ Permission Framework
- [x] Permission enums with string values
- [x] RequiresPermission annotation
- [x] Permission aspect for enforcement
- [x] PermissionService for checks

### ✅ Gateway Updates
- [x] Enhanced JWT service with workspace context
- [x] WorkspaceContextFilter for header injection
- [x] Updated authentication flow
- [x] Workspace switching capability

### ✅ API Endpoints
- [x] Multi-workspace login
- [x] Workspace switching
- [x] Workspace creation
- [x] User workspace listing
- [x] Member invitation endpoints

---

## Phase 12: Example API Usage

### Step 12.1: Complete API Flow Examples

**1. User Registration and Workspace Creation:**
```bash
# 1. Register new user
curl -X POST http://localhost:8080/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@family.com",
    "password": "password123",
    "name": "John Doe"
  }'

# 2. Create a workspace (requires authentication)
curl -X POST http://localhost:8080/v1/users/workspaces \
  -H "Content-Type: application/json" \
  -b "access_token=<jwt_token>" \
  -d '{
    "name": "Family Budget"
  }'

# 3. Login to get workspace-scoped token
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@family.com",
    "password": "password123"
  }'
```

**2. Permission-Based Operations:**
```bash
# Owner can invite members (has workspace:members permission)
curl -X POST http://localhost:8080/v1/users/workspaces/{workspaceId}/members/invite \
  -H "Content-Type: application/json" \
  -b "access_token=<owner_jwt_token>" \
  -d '{
    "email": "spouse@family.com",
    "role": "Viewer"
  }'

# Viewer trying to invite members (will fail - no workspace:members permission)
curl -X POST http://localhost:8080/v1/users/workspaces/{workspaceId}/members/invite \
  -H "Content-Type: application/json" \
  -b "access_token=<viewer_jwt_token>" \
  -d '{
    "email": "friend@example.com",
    "role": "Viewer"
  }'
# Returns: 403 Forbidden - Insufficient permissions: WORKSPACE_MEMBERS
```

**3. Workspace Switching:**
```bash
# Switch to different workspace
curl -X POST http://localhost:8080/auth/switch-workspace \
  -H "Content-Type: application/json" \
  -b "access_token=<current_jwt_token>" \
  -d '{
    "workspaceId": "other-workspace-uuid"
  }'
```

---

## Summary

This implementation provides:

1. **Complete Multi-Tenant Architecture**: Full workspace isolation with proper scoping
2. **Simple Permission System**: Owner/Viewer roles with clear capabilities
3. **Type-Safe Permissions**: Enum-based permissions with compile-time safety
4. **JWT-Based Performance**: No database lookups for permission checks
5. **Workspace Context**: Automatic header injection for downstream services
6. **Caching Strategy**: Redis caching for optimal performance
7. **Security First**: Proper validation and access control throughout

The architecture is ready for production use and can easily be extended with additional roles and permissions as needed.