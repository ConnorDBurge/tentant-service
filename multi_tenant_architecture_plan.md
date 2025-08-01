# Multi-Tenant Architecture Implementation Plan

## Overview

This document outlines the implementation plan for transforming the existing Beaver microservices architecture into a multi-tenant system with workspace-based isolation and simple role-based permissions. Following industry best practices, we'll expand the user-service to own all identity concerns with a simplified two-role system.

## Current Architecture Analysis

### Existing Services
- **Core Gateway Service (Port 8080)**: Spring Cloud Gateway with JWT auth, routing, rate limiting
- **User Service (Port 8081)**: User management with PostgreSQL and Redis caching
- **Infrastructure**: Clean service-to-service communication with shared secrets

### Current Strengths
- ✅ Solid JWT-based authentication
- ✅ Proper service isolation with gateway filters
- ✅ Redis caching for performance
- ✅ Flyway database migrations
- ✅ Comprehensive error handling

## Target Multi-Tenant Architecture

### Single Service Approach (Industry Standard)
Following the pattern used by GitHub, Slack, and Linear, we'll expand the **user-service** to become a comprehensive **identity service** that owns:

1. **Users**: Individual user accounts
2. **Workspaces**: Company/team/family entities
3. **Memberships**: User-workspace relationships with roles
4. **Permissions**: Simple two-tier access control system

### Enhanced JWT Structure
```json
{
  "userId": "550e8400-e29b-41d4-a716-446655440000",
  "email": "john@acme.com", 
  "name": "John Doe",
  "workspaceId": "660e8400-e29b-41d4-a716-446655440001",
  "permissions": ["transaction:read", "transaction:write", "budget:read", "budget:write"],
  "type": "access"
}
```

## Simplified Permission System

### Two-Role System
1. **Owner**: Full access to everything in the workspace
2. **Viewer**: Read-only access to all data

### Permission Enum
```java
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
}
```

### Role Definitions
```java
// Owner Role Permissions
Set.of(
    Permission.TRANSACTION_READ, Permission.TRANSACTION_WRITE,
    Permission.BUDGET_READ, Permission.BUDGET_WRITE, 
    Permission.REPORT_READ,
    Permission.WORKSPACE_SETTINGS, Permission.WORKSPACE_MEMBERS
)

// Viewer Role Permissions  
Set.of(
    Permission.TRANSACTION_READ, Permission.BUDGET_READ, Permission.REPORT_READ
)
```

## Implementation Plan

### Phase 1: Enhanced User Service Database Schema (Week 1)

#### 1.1 New Database Tables

**V3__create_workspaces_table.sql:**
```sql
-- Workspaces
CREATE TABLE workspaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    plan VARCHAR(20) NOT NULL DEFAULT 'STARTER',
    trial_ends_at TIMESTAMP WITH TIME ZONE,
    settings JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_workspaces_status ON workspaces(status);
```

**V4__create_permissions_table.sql:**
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
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Insert simplified permissions
INSERT INTO permissions (code, name, description, resource, action, category) VALUES
('transaction:read', 'Read Transactions', 'View transaction history and details', 'transaction', 'read', 'FINANCIAL'),
('transaction:write', 'Write Transactions', 'Create and edit transactions', 'transaction', 'write', 'FINANCIAL'),
('budget:read', 'Read Budgets', 'View budget information', 'budget', 'read', 'FINANCIAL'),
('budget:write', 'Write Budgets', 'Create and edit budgets', 'budget', 'write', 'FINANCIAL'),
('report:read', 'Read Reports', 'View reports and analytics', 'report', 'read', 'REPORTING'),
('workspace:settings', 'Workspace Settings', 'Modify workspace settings', 'workspace', 'settings', 'ADMINISTRATION'),
('workspace:members', 'Manage Members', 'Add and remove workspace members', 'workspace', 'members', 'ADMINISTRATION');
```

**V5__create_roles_table.sql:**
```sql
-- Simplified Roles (only Owner and Viewer)
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_system_role BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(workspace_id, name)
);

-- Role-Permission junction
CREATE TABLE role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);
```

**V6__create_workspace_memberships_table.sql:**
```sql
-- Workspace Memberships
CREATE TABLE workspace_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    joined_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, workspace_id)
);

CREATE INDEX idx_workspace_memberships_user_id ON workspace_memberships(user_id);
CREATE INDEX idx_workspace_memberships_workspace_id ON workspace_memberships(workspace_id);
```

#### 1.2 Enhanced Entity Classes

**Workspace Entity:**
```java
package com.beaver.userservice.workspace.entity;

import com.beaver.userservice.common.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.DynamicUpdate;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
@DynamicUpdate
@Entity
@Table(name = "workspaces")
public class Workspace extends BaseEntity {

    @Column(nullable = false)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private WorkspaceStatus status = WorkspaceStatus.ACTIVE;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PlanType plan = PlanType.STARTER;

    @Column(name = "trial_ends_at")
    private LocalDateTime trialEndsAt;

    @Column(columnDefinition = "jsonb")
    private String settings;
}

enum WorkspaceStatus {
    ACTIVE, SUSPENDED, TRIAL
}

enum PlanType {
    STARTER, PROFESSIONAL, ENTERPRISE
}
```

**Permission and Role Entities:**
```java
package com.beaver.userservice.permission.entity;

import com.beaver.userservice.common.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

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

@Data
@NoArgsConstructor
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
@Entity
@Table(name = "roles")
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

enum PermissionCategory {
    FINANCIAL, ADMINISTRATION, REPORTING
}
```

**Simplified Workspace Membership Entity:**
```java
package com.beaver.userservice.membership.entity;

import com.beaver.userservice.common.entity.BaseEntity;
import com.beaver.userservice.workspace.entity.Workspace;
import com.beaver.userservice.permission.entity.Role;
import com.beaver.userservice.user.entity.User;
import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

@Data
@NoArgsConstructor
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
@Entity
@Table(name = "workspace_memberships")
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

enum MembershipStatus {
    ACTIVE, SUSPENDED, PENDING
}
```

### Phase 2: Enhanced User Service Business Logic (Week 1-2)

#### 2.1 Updated User Service Structure

```
src/main/java/com/beaver/userservice/
├── user/                           # Existing
├── workspace/                      # NEW
│   ├── entity/Workspace.java
│   ├── WorkspaceService.java
│   ├── WorkspaceController.java
│   └── WorkspaceRepository.java
├── membership/                     # NEW
│   ├── entity/WorkspaceMembership.java
│   ├── MembershipService.java
│   ├── MembershipController.java
│   └── MembershipRepository.java
├── permission/                     # NEW - Simplified
│   ├── entity/Permission.java
│   ├── entity/Role.java
│   ├── PermissionService.java
│   ├── RoleService.java
│   └── repositories/
└── auth/                          # NEW - Authentication domain
    ├── AuthService.java
    ├── dto/AuthResponseDto.java
    └── dto/UserWithWorkspacesDto.java
```

#### 2.2 Simplified Default Role Service

```java
package com.beaver.userservice.permission;

import com.beaver.userservice.permission.entity.Permission;
import com.beaver.userservice.permission.entity.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional
public class DefaultRoleService {
    
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    
    public void createDefaultRoles(UUID workspaceId) {
        // Owner role - full access
        Role owner = createRole(workspaceId, "Owner", "Full access to all workspace resources", true);
        Set<Permission> allPermissions = Set.copyOf(permissionRepository.findAll());
        owner.setPermissions(allPermissions);
        roleRepository.save(owner);
        
        // Viewer role - read-only access
        Role viewer = createRole(workspaceId, "Viewer", "Read-only access to workspace data", true);
        Set<Permission> viewerPermissions = permissionRepository.findByCodeIn(Set.of(
            "transaction:read", "budget:read", "report:read"
        ));
        viewer.setPermissions(viewerPermissions);
        roleRepository.save(viewer);
    }
    
    private Role createRole(UUID workspaceId, String name, String description, boolean isSystemRole) {
        return Role.builder()
                .workspaceId(workspaceId)
                .name(name)
                .description(description)
                .isSystemRole(isSystemRole)
                .build();
    }
}
```

#### 2.3 Enhanced Authentication Service

```java
package com.beaver.userservice.auth;

import com.beaver.userservice.auth.dto.UserWithWorkspacesDto;
import com.beaver.userservice.membership.MembershipService;
import com.beaver.userservice.user.UserService;
import com.beaver.userservice.user.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    
    private final UserService userService;
    private final MembershipService membershipService;
    private final PasswordEncoder passwordEncoder;
    
    public UserWithWorkspacesDto validateCredentialsWithWorkspaces(String email, String password) {
        User user = userService.findByEmail(email)
                .orElseThrow(() -> new InvalidUserDataException("Invalid credentials"));

        if (!user.isActive() || !passwordEncoder.matches(password, user.getPassword())) {
            throw new InvalidUserDataException("Invalid credentials");
        }

        // Get user's workspace memberships with permissions
        List<WorkspaceMembership> memberships = membershipService.findActiveByUserId(user.getId());
        
        return UserWithWorkspacesDto.fromUserAndMemberships(user, memberships);
    }
    
    public WorkspaceMembership validateUserWorkspaceAccess(UUID userId, UUID workspaceId) {
        return membershipService.findByUserIdAndWorkspaceId(userId, workspaceId)
                .filter(membership -> membership.getStatus() == MembershipStatus.ACTIVE)
                .orElseThrow(() -> new AccessDeniedException("No access to workspace"));
    }
}
```

#### 2.4 Updated Internal API Controller

```java
package com.beaver.userservice.internal;

import com.beaver.userservice.auth.AuthService;
import com.beaver.userservice.auth.dto.UserWithWorkspacesDto;
import com.beaver.userservice.internal.dto.CredentialsRequest;
import com.beaver.userservice.membership.entity.WorkspaceMembership;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/internal")
@RequiredArgsConstructor
public class InternalAuthController {

    private final AuthService authService;

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
}
```

### Phase 3: Enhanced Gateway Service (Week 2)

#### 3.1 Updated JWT Service

```java
package com.beaver.core.service;

@Service
public class JwtService {
    
    // Enhanced token generation with workspace context
    public String generateAccessToken(String userId, String email, String name, 
                                    String workspaceId, Set<String> permissions) {
        return generateToken(Map.of(
            "userId", userId,
            "email", email,
            "name", name,
            "workspaceId", workspaceId,
            "permissions", permissions,
            "type", "access"
        ), jwtConfig.getAccessTokenValidity() * 60 * 1000);
    }
    
    public Mono<String> extractWorkspaceId(String token) {
        return extractClaim(token, claims -> claims.get("workspaceId", String.class));
    }
    
    public Mono<Set<String>> extractPermissions(String token) {
        return extractClaim(token, claims -> {
            List<String> perms = claims.get("permissions", List.class);
            return perms != null ? new HashSet<>(perms) : new HashSet<>();
        });
    }
}
```

#### 3.2 Simplified User Service Client

```java
package com.beaver.core.client;

@Component
@RequiredArgsConstructor
public class UserServiceClient {
    
    // New method for multi-workspace authentication
    public Mono<UserWithWorkspacesDto> validateCredentialsWithWorkspaces(String email, String password) {
        CredentialsRequest request = CredentialsRequest.builder()
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
                .bodyToMono(UserWithWorkspacesDto.class);
    }
    
    public Mono<WorkspaceMembershipDto> validateWorkspaceAccess(UUID userId, UUID workspaceId) {
        return getUserServiceWebClient()
                .post()
                .uri("/users/internal/validate-workspace-access")
                .header("X-Service-Secret", gatewaySecret)
                .header("X-Source", "gateway")
                .queryParam("userId", userId)
                .queryParam("workspaceId", workspaceId)
                .retrieve()
                .bodyToMono(WorkspaceMembershipDto.class);
    }
}
```

#### 3.3 Updated Authentication Controller

```java
package com.beaver.core.controller;

@RestController
@RequestMapping("/auth")
public class AuthController {
    
    @PostMapping("/login")
    public Mono<ResponseEntity<AuthResponse>> login(@Valid @RequestBody LoginRequest request) {
        return userServiceClient.validateCredentialsWithWorkspaces(request.email(), request.password())
            .flatMap(userWithWorkspaces -> {
                if (userWithWorkspaces.getWorkspaces().isEmpty()) {
                    return Mono.error(new AuthenticationFailedException("No workspace access"));
                }
                
                // Select primary workspace (first active one, or let user choose)
                WorkspaceMembershipDto primaryMembership = selectPrimaryWorkspace(userWithWorkspaces.getWorkspaces());
                
                return createAuthResponse(userWithWorkspaces.getUser(), primaryMembership, "Login successful");
            });
    }
    
    @PostMapping("/switch-workspace")
    public Mono<ResponseEntity<AuthResponse>> switchWorkspace(
            @CookieValue("access_token") String accessToken,
            @RequestBody SwitchWorkspaceRequest request) {
        
        return jwtService.extractUserId(accessToken)
            .flatMap(userId -> 
                userServiceClient.validateWorkspaceAccess(
                    UUID.fromString(userId), 
                    UUID.fromString(request.workspaceId())
                )
                .flatMap(membership -> 
                    userServiceClient.getUserById(UUID.fromString(userId))
                        .flatMap(userMap -> createAuthResponse(
                            UserDto.fromMap(userMap),
                            membership,
                            "Workspace switched successfully"
                        ))
                )
            );
    }
    
    private Mono<ResponseEntity<AuthResponse>> createAuthResponse(
            UserDto user, WorkspaceMembershipDto membership, String message) {

        String accessToken = jwtService.generateAccessToken(
                user.getId().toString(),
                user.getEmail(),
                user.getName(),
                membership.getWorkspace().getId().toString(),
                membership.getAllPermissions()
        );
        
        String refreshToken = jwtService.generateRefreshToken(user.getId().toString());

        // ... cookie creation and response building
    }
    
    private WorkspaceMembershipDto selectPrimaryWorkspace(List<WorkspaceMembershipDto> memberships) {
        // For now, just return the first one
        // Later you could add logic for "last used workspace" or let user choose
        return memberships.get(0);
    }
}
```

#### 3.4 Simplified Context Filter

```java
package com.beaver.core.security;

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
                    jwtService.extractWorkspaceId(token),
                    jwtService.extractPermissions(token)
                ).flatMap(tuple -> {
                    String userId = tuple.getT1();
                    String workspaceId = tuple.getT2();
                    Set<String> permissions = tuple.getT3();
                    
                    var modifiedRequest = exchange.getRequest().mutate()
                            .header("X-User-Id", userId)
                            .header("X-Workspace-Id", workspaceId)
                            .header("X-User-Permissions", String.join(",", permissions))
                            .build();
                    
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

### Phase 4: Type-Safe Permission Framework (Week 2-3)

#### 4.1 Permission Enums and Annotation

```java
package com.beaver.shared.permission;

public enum Permission {
    // Transaction permissions
    TRANSACTION_READ("transaction:read"),
    TRANSACTION_WRITE("transaction:write"),
    
    // Budget permissions
    BUDGET_READ("budget:read"),
    BUDGET_WRITE("budget:write"),
    
    // Report permissions
    REPORT_READ("report:read"),
    
    // Workspace permissions
    WORKSPACE_SETTINGS("workspace:settings"),
    WORKSPACE_MEMBERS("workspace:members");
    
    private final String code;
    
    Permission(String code) {
        this.code = code;
    }
    
    public String getCode() {
        return code;
    }
    
    @Override
    public String toString() {
        return code;
    }
}

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiresPermission {
    Permission[] value(); // Required permissions as enums directly
    boolean requireAll() default false; // false = OR logic, true = AND logic
}
```

#### 4.2 Permission Aspect

```java
package com.beaver.shared.permission;

@Aspect
@Component
@RequiredArgsConstructor
public class PermissionAspect {
    
    private final PermissionService permissionService;
    
    @Around("@annotation(requiresPermission)")
    public Object checkPermission(ProceedingJoinPoint joinPoint, RequiresPermission requiresPermission) throws Throwable {
        
        RequestAttributes attributes = RequestContextHolder.currentRequestAttributes();
        HttpServletRequest request = ((ServletRequestAttributes) attributes).getRequest();
        
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
                permissionService.hasPermission(userPermissions, perm.getCode())) :
            Arrays.stream(requiredPermissions).anyMatch(perm -> 
                permissionService.hasPermission(userPermissions, perm.getCode()));
        
        if (!hasAccess) {
            String permissionNames = Arrays.stream(requiredPermissions)
                    .map(Permission::name)
                    .collect(Collectors.joining(", "));
            throw new AccessDeniedException("Insufficient permissions: " + permissionNames);
        }
        
        return joinPoint.proceed();
    }
}
```

#### 4.3 Simplified Permission Service

```java
package com.beaver.shared.permission;

@Service
@RequiredArgsConstructor
public class PermissionService {
    
    public boolean hasPermission(Set<String> userPermissions, String requiredPermission) {
        // Direct permission check
        return userPermissions.contains(requiredPermission);
    }
    
    public boolean isOwner(Set<String> userPermissions) {
        return userPermissions.contains(Permission.WORKSPACE_SETTINGS.getCode());
    }
    
    public boolean canRead(Set<String> userPermissions, String resource) {
        return userPermissions.contains(resource + ":read");
    }
    
    public boolean canWrite(Set<String> userPermissions, String resource) {
        return userPermissions.contains(resource + ":write");
    }
}
```

### Phase 5: Downstream Service Examples (Week 3)

#### 5.1 Financial Service Controllers with Clean Type-Safe Permissions

```java
package com.beaver.financialservice.transaction;

import com.beaver.shared.permission.RequiresPermission;
import com.beaver.shared.permission.Permission;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/transactions")
@RequiredArgsConstructor
public class TransactionController {
    
    private final TransactionService transactionService;
    
    @GetMapping
    @RequiresPermission(Permission.TRANSACTION_READ)
    public ResponseEntity<List<TransactionDto>> getTransactions(
            @RequestHeader("X-User-Id") UUID userId,
            @RequestHeader("X-Workspace-Id") UUID workspaceId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        
        List<Transaction> transactions = transactionService.findByWorkspaceId(workspaceId, page, size);
        return ResponseEntity.ok(transactions.stream()
                .map(TransactionDto::fromEntity)
                .toList());
    }
    
    @GetMapping("/{id}")
    @RequiresPermission(Permission.TRANSACTION_READ)
    public ResponseEntity<TransactionDto> getTransaction(
            @PathVariable UUID id,
            @RequestHeader("X-Workspace-Id") UUID workspaceId) {
        
        Transaction transaction = transactionService.findByIdAndWorkspace(id, workspaceId);
        return ResponseEntity.ok(TransactionDto.fromEntity(transaction));
    }
    
    @PostMapping
    @RequiresPermission(Permission.TRANSACTION_WRITE)
    public ResponseEntity<TransactionDto> createTransaction(
            @RequestHeader("X-User-Id") UUID userId,
            @RequestHeader("X-Workspace-Id") UUID workspaceId,
            @Valid @RequestBody CreateTransactionRequest request) {
        
        Transaction transaction = transactionService.create(request, workspaceId, userId);
        return ResponseEntity.ok(TransactionDto.fromEntity(transaction));
    }
    
    @PutMapping("/{id}")
    @RequiresPermission(Permission.TRANSACTION_WRITE)
    public ResponseEntity<TransactionDto> updateTransaction(
            @PathVariable UUID id,
            @RequestHeader("X-User-Id") UUID userId,
            @RequestHeader("X-Workspace-Id") UUID workspaceId,
            @Valid @RequestBody UpdateTransactionRequest request) {
        
        Transaction transaction = transactionService.update(id, request, workspaceId, userId);
        return ResponseEntity.ok(TransactionDto.fromEntity(transaction));
    }
    
    @DeleteMapping("/{id}")
    @RequiresPermission(Permission.TRANSACTION_WRITE)
    public ResponseEntity<Void> deleteTransaction(
            @PathVariable UUID id,
            @RequestHeader("X-Workspace-Id") UUID workspaceId) {
        
        transactionService.delete(id, workspaceId);
        return ResponseEntity.noContent().build();
    }
    
    @PostMapping("/bulk-import")
    @RequiresPermission(value = {Permission.TRANSACTION_WRITE, Permission.WORKSPACE_SETTINGS}, requireAll = true)
    public ResponseEntity<BulkImportResult> bulkImport(
            @RequestHeader("X-User-Id") UUID userId,
            @RequestHeader("X-Workspace-Id") UUID workspaceId,
            @RequestBody BulkImportRequest request) {
        
        // Requires BOTH Transaction.WRITE AND Workspace.SETTINGS (Owner only)
        BulkImportResult result = transactionService.bulkImport(request, workspaceId, userId);
        return ResponseEntity.ok(result);
    }
    
    @GetMapping("/analytics")
    @RequiresPermission(Permission.TRANSACTION_READ)
    public ResponseEntity<TransactionAnalytics> getAnalytics(
            @RequestHeader("X-Workspace-Id") UUID workspaceId,
            @RequestParam String period) {
        
        TransactionAnalytics analytics = transactionService.getAnalytics(workspaceId, period);
        return ResponseEntity.ok(analytics);
    }
    
    @DeleteMapping("/bulk")
    @RequiresPermission({Permission.TRANSACTION_WRITE, Permission.WORKSPACE_SETTINGS}) // Either permission works (OR logic)
    public ResponseEntity<Void> bulkDelete(
            @RequestHeader("X-Workspace-Id") UUID workspaceId,
            @RequestBody List<UUID> transactionIds) {
        
        // Owner has WORKSPACE_SETTINGS ✅
        // Future "Financial Manager" role with TRANSACTION_WRITE would also work ✅
        transactionService.bulkDelete(workspaceId, transactionIds);
        return ResponseEntity.noContent().build();
    }
}
```

#### 5.2 Budget Controller with Clean Type-Safe Permissions

```java
package com.beaver.financialservice.budget;

import com.beaver.shared.permission.RequiresPermission;
import com.beaver.shared.permission.Permission;

@RestController
@RequestMapping("/budgets")
@RequiredArgsConstructor
public class BudgetController {
    
    private final BudgetService budgetService;
    
    @GetMapping
    @RequiresPermission(Permission.BUDGET_READ)
    public ResponseEntity<List<BudgetDto>> getBudgets(
            @RequestHeader("X-Workspace-Id") UUID workspaceId) {
        
        List<Budget> budgets = budgetService.findByWorkspaceId(workspaceId);
        return ResponseEntity.ok(budgets.stream()
                .map(BudgetDto::fromEntity)
                .toList());
    }
    
    @PostMapping
    @RequiresPermission(Permission.BUDGET_WRITE)
    public ResponseEntity<BudgetDto> createBudget(
            @RequestHeader("X-User-Id") UUID userId,
            @RequestHeader("X-Workspace-Id") UUID workspaceId,
            @Valid @RequestBody CreateBudgetRequest request) {
        
        Budget budget = budgetService.create(request, workspaceId, userId);
        return ResponseEntity.ok(BudgetDto.fromEntity(budget));
    }
    
    @PutMapping("/{id}")
    @RequiresPermission(Permission.BUDGET_WRITE)
    public ResponseEntity<BudgetDto> updateBudget(
            @PathVariable UUID id,
            @RequestHeader("X-Workspace-Id") UUID workspaceId,
            @Valid @RequestBody UpdateBudgetRequest request) {
        
        Budget budget = budgetService.update(id, request, workspaceId);
        return ResponseEntity.ok(BudgetDto.fromEntity(budget));
    }
    
    @DeleteMapping("/{id}")
    @RequiresPermission(Permission.BUDGET_WRITE)
    public ResponseEntity<Void> deleteBudget(
            @PathVariable UUID id,
            @RequestHeader("X-Workspace-Id") UUID workspaceId) {
        
        budgetService.delete(id, workspaceId);
        return ResponseEntity.noContent().build();
    }
    
    @GetMapping("/{id}/vs-actual")
    @RequiresPermission(Permission.BUDGET_READ)
    public ResponseEntity<BudgetVsActualReport> getBudgetVsActual(
            @PathVariable UUID id,
            @RequestHeader("X-Workspace-Id") UUID workspaceId,
            @RequestParam String period) {
        
        BudgetVsActualReport report = budgetService.getBudgetVsActual(id, workspaceId, period);
        return ResponseEntity.ok(report);
    }
}
```

#### 5.3 Workspace Management Controller

```java
package com.beaver.financialservice.workspace;

import com.beaver.shared.permission.RequiresPermission;
import com.beaver.shared.permission.Permission;

@RestController
@RequestMapping("/workspace")
@RequiredArgsConstructor
public class WorkspaceController {
    
    private final WorkspaceService workspaceService;
    
    @GetMapping("/members")
    @RequiresPermission(Permission.WORKSPACE_MEMBERS)
    public ResponseEntity<List<WorkspaceMemberDto>> getMembers(
            @RequestHeader("X-Workspace-Id") UUID workspaceId) {
        
        List<WorkspaceMember> members = workspaceService.getMembers(workspaceId);
        return ResponseEntity.ok(members.stream()
                .map(WorkspaceMemberDto::fromEntity)
                .toList());
    }
    
    @PostMapping("/members/invite")
    @RequiresPermission(Permission.WORKSPACE_MEMBERS)
    public ResponseEntity<Void> inviteMember(
            @RequestHeader("X-User-Id") UUID inviterId,
            @RequestHeader("X-Workspace-Id") UUID workspaceId,
            @Valid @RequestBody InviteMemberRequest request) {
        
        workspaceService.inviteMember(workspaceId, request.email(), request.role(), inviterId);
        return ResponseEntity.ok().build();
    }
    
    @PatchMapping("/settings")
    @RequiresPermission(Permission.WORKSPACE_SETTINGS)
    public ResponseEntity<WorkspaceDto> updateSettings(
            @RequestHeader("X-Workspace-Id") UUID workspaceId,
            @Valid @RequestBody UpdateWorkspaceRequest request) {
        
        Workspace workspace = workspaceService.updateSettings(workspaceId, request);
        return ResponseEntity.ok(WorkspaceDto.fromEntity(workspace));
    }
}
```

#### 5.4 Workspace-Scoped Entities

```java
package com.beaver.financialservice.transaction.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

@Data
@NoArgsConstructor
@SuperBuilder
@Entity
@Table(name = "transactions")
public class Transaction extends BaseEntity {

    @Column(name = "workspace_id", nullable = false)
    private UUID workspaceId; // Workspace scoping

    @Column(name = "user_id", nullable = false)
    private UUID userId; // Who created the transaction

    @Column(nullable = false)
    private String description;

    @Column(nullable = false, precision = 19, scale = 2)
    private BigDecimal amount;

    @Column(name = "transaction_date", nullable = false)
    private LocalDateTime transactionDate;

    @Column(nullable = false)
    private String category;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private TransactionType type; // INCOME, EXPENSE

    // Indexes for workspace scoping
    @Table(indexes = {
        @Index(name = "idx_transactions_workspace_id", columnList = "workspace_id"),
        @Index(name = "idx_transactions_user_id", columnList = "user_id"),
        @Index(name = "idx_transactions_date", columnList = "transaction_date")
    })
}

enum TransactionType {
    INCOME, EXPENSE
}
```

#### 5.5 Workspace-Scoped Service Layer

```java
package com.beaver.financialservice.transaction;

import com.beaver.financialservice.common.exception.ResourceNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class TransactionService {
    
    private final TransactionRepository transactionRepository;
    
    public List<Transaction> findByWorkspaceId(UUID workspaceId, int page, int size) {
        PageRequest pageRequest = PageRequest.of(page, size);
        return transactionRepository.findByWorkspaceIdOrderByTransactionDateDesc(workspaceId, pageRequest);
    }
    
    public Transaction findByIdAndWorkspace(UUID id, UUID workspaceId) {
        return transactionRepository.findByIdAndWorkspaceId(id, workspaceId)
                .orElseThrow(() -> new ResourceNotFoundException("Transaction not found"));
    }
    
    public Transaction create(CreateTransactionRequest request, UUID workspaceId, UUID userId) {
        Transaction transaction = Transaction.builder()
                .workspaceId(workspaceId)
                .userId(userId)
                .description(request.description())
                .amount(request.amount())
                .transactionDate(request.transactionDate())
                .category(request.category())
                .type(request.type())
                .build();
                
        return transactionRepository.save(transaction);
    }
    
    public Transaction update(UUID id, UpdateTransactionRequest request, UUID workspaceId, UUID userId) {
        Transaction existing = findByIdAndWorkspace(id, workspaceId);
        
        existing.setDescription(request.description());
        existing.setAmount(request.amount());
        existing.setTransactionDate(request.transactionDate());
        existing.setCategory(request.category());
        existing.setType(request.type());
        
        return transactionRepository.save(existing);
    }
    
    public void delete(UUID id, UUID workspaceId) {
        Transaction transaction = findByIdAndWorkspace(id, workspaceId);
        transactionRepository.delete(transaction);
    }
    
    @Cacheable(value = "transaction-analytics", key = "#workspaceId + ':' + #period")
    public TransactionAnalytics getAnalytics(UUID workspaceId, String period) {
        // Calculate analytics for the workspace
        return transactionRepository.calculateAnalytics(workspaceId, period);
    }
    
    public BulkImportResult bulkImport(BulkImportRequest request, UUID workspaceId, UUID userId) {
        List<Transaction> transactions = request.transactions().stream()
                .map(dto -> Transaction.builder()
                        .workspaceId(workspaceId)
                        .userId(userId)
                        .description(dto.description())
                        .amount(dto.amount())
                        .transactionDate(dto.transactionDate())
                        .category(dto.category())
                        .type(dto.type())
                        .build())
                .toList();
        
        List<Transaction> saved = transactionRepository.saveAll(transactions);
        
        return BulkImportResult.builder()
                .totalProcessed(transactions.size())
                .successfulImports(saved.size())
                .failedImports(0)
                .build();
    }
}
```

### Phase 6: Workspace Creation and Management (Week 3-4)

#### 6.1 Simplified Workspace Creation Flow

```java
package com.beaver.userservice.workspace;

@Service
@RequiredArgsConstructor
@Transactional
public class WorkspaceService {
    
    private final WorkspaceRepository workspaceRepository;
    private final MembershipService membershipService;
    private final DefaultRoleService defaultRoleService;
    private final RoleRepository roleRepository;
    
    public Workspace createWorkspace(CreateWorkspaceRequest request, UUID ownerId) {
        // Create workspace
        Workspace workspace = Workspace.builder()
                .name(request.name())
                .status(WorkspaceStatus.TRIAL)
                .plan(PlanType.STARTER)
                .trialEndsAt(LocalDateTime.now().plusDays(14)) // 14-day trial
                .build();
        
        workspace = workspaceRepository.save(workspace);
        
        // Create default roles (Owner and Viewer) for this workspace
        defaultRoleService.createDefaultRoles(workspace.getId());
        
        // Add creator as owner
        Role ownerRole = roleRepository.findByWorkspaceIdAndName(workspace.getId(), "Owner")
                .orElseThrow(() -> new IllegalStateException("Owner role not found"));
        
        membershipService.addUserToWorkspace(ownerId, workspace.getId(), ownerRole);
        
        return workspace;
    }
    
    public List<WorkspaceMember> getMembers(UUID workspaceId) {
        return membershipService.findMembersByWorkspaceId(workspaceId);
    }
    
    public void inviteMember(UUID workspaceId, String email, String roleName, UUID inviterId) {
        // Find the role (Owner or Viewer)
        Role role = roleRepository.findByWorkspaceIdAndName(workspaceId, roleName)
                .orElseThrow(() -> new IllegalArgumentException("Invalid role: " + roleName));
        
        // Send invitation logic here
        // For now, we'll create the membership directly if user exists
        User user = userService.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + email));
        
        membershipService.addUserToWorkspace(user.getId(), workspaceId, role);
    }
}
```

#### 6.2 Simplified Membership Service

```java
package com.beaver.userservice.membership;

import com.beaver.userservice.membership.entity.WorkspaceMembership;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class MembershipService {
    
    private final MembershipRepository membershipRepository;
    
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
    
    public WorkspaceMembership addUserToWorkspace(UUID userId, UUID workspaceId, Role role) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
        
        Workspace workspace = workspaceRepository.findById(workspaceId)
                .orElseThrow(() -> new WorkspaceNotFoundException("Workspace not found"));
        
        WorkspaceMembership membership = WorkspaceMembership.builder()
                .user(user)
                .workspace(workspace)
                .role(role)
                .status(MembershipStatus.ACTIVE)
                .joinedAt(LocalDateTime.now())
                .build();
        
        return membershipRepository.save(membership);
    }
    
    public void changeUserRole(UUID userId, UUID workspaceId, String newRoleName) {
        WorkspaceMembership membership = findByUserIdAndWorkspaceId(userId, workspaceId)
                .orElseThrow(() -> new MembershipNotFoundException("Membership not found"));
        
        Role newRole = roleRepository.findByWorkspaceIdAndName(workspaceId, newRoleName)
                .orElseThrow(() -> new IllegalArgumentException("Invalid role: " + newRoleName));
        
        membership.setRole(newRole);
        membershipRepository.save(membership);
        
        // Clear cache
        evictMembershipCache(userId, workspaceId);
    }
}
```

### Phase 7: Gateway Configuration and API Examples (Week 4)

#### 7.1 Updated Gateway Routes

```yaml
# src/main/resources/application.yml
spring:
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
        
        - id: financial-service
          uri: ${financial-service.url:http://localhost:8082}
          predicates:
            - Path=/v1/financial/**
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
```

#### 7.2 Example API Usage

**1. User Login (gets access to workspace):**
```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@family.com",
    "password": "password123"
  }'
```

**Response includes JWT with workspace context:**
```json
{
  "message": "Login successful",
  "userId": "550e8400-e29b-41d4-a716-446655440000",
  "email": "john@family.com",
  "name": "John Doe"
}
```

**2. Create Transaction (Owner can write):**
```bash
curl -X POST http://localhost:8080/v1/financial/transactions \
  -H "Content-Type: application/json" \
  -b "access_token=<jwt_token>" \
  -d '{
    "description": "Grocery shopping",
    "amount": 85.50,
    "transactionDate": "2025-01-15T10:30:00",
    "category": "Food",
    "type": "EXPENSE"
  }'
```

**3. View Transactions (Both Owner and Viewer can read):**
```bash
curl -X GET "http://localhost:8080/v1/financial/transactions?page=0&size=10" \
  -H "Content-Type: application/json" \
  -b "access_token=<jwt_token>"
```

**4. Invite Family Member (Owner only):**
```bash
curl -X POST http://localhost:8080/v1/financial/workspace/members/invite \
  -H "Content-Type: application/json" \
  -b "access_token=<jwt_token>" \
  -d '{
    "email": "spouse@family.com",
    "role": "Viewer"
  }'
```

#### 7.3 Permission Enforcement Examples

**Single Permission (default OR logic):**
```java
@GetMapping("/transactions")
@RequiresPermission(Permission.TRANSACTION_READ)  // ✅ Works for both Owner and Viewer
public ResponseEntity<List<TransactionDto>> getTransactions(...) {
    // Both Owner and Viewer have TRANSACTION_READ
}
```

**Multiple Permissions with OR logic (default):**
```java
@DeleteMapping("/bulk")
@RequiresPermission({Permission.TRANSACTION_WRITE, Permission.WORKSPACE_SETTINGS}) // Either permission works
public ResponseEntity<Void> bulkDelete(...) {
    // Owner has WORKSPACE_SETTINGS ✅
    // Future "Financial Manager" role with TRANSACTION_WRITE would also work ✅
    // Viewer has neither ❌
}
```

**Multiple Permissions with AND logic:**
```java
@PostMapping("/bulk-import")
@RequiresPermission(value = {Permission.TRANSACTION_WRITE, Permission.WORKSPACE_SETTINGS}, requireAll = true)
public ResponseEntity<BulkImportResult> bulkImport(...) {
    // Requires BOTH permissions - only Owner has both ✅
    // Viewer has neither ❌
    // Future role with only TRANSACTION_WRITE would fail ❌
}
```

**Viewer trying to create transaction:**
```java
// Viewer has only TRANSACTION_READ, BUDGET_READ, REPORT_READ
// This will throw AccessDeniedException

@PostMapping("/transactions")
@RequiresPermission(Permission.TRANSACTION_WRITE)  // ❌ Viewer doesn't have this
public ResponseEntity<TransactionDto> createTransaction(...) {
    // Never reached for Viewer
}
```

**Owner can do everything:**
```java
// Owner has all permissions

@PostMapping("/transactions")
@RequiresPermission(Permission.TRANSACTION_WRITE)  // ✅ Owner has this permission
public ResponseEntity<TransactionDto> createTransaction(...) {
    // Successfully executed for Owner
}

@PostMapping("/workspace/members/invite")
@RequiresPermission(Permission.WORKSPACE_MEMBERS)  // ✅ Owner has this permission
public ResponseEntity<Void> inviteMember(...) {
    // Successfully executed for Owner
}
```

#### 7.4 Headers Flow in Downstream Services

**Gateway adds these headers automatically:**
```
X-User-Id: 550e8400-e29b-41d4-a716-446655440000
X-Workspace-Id: 660e8400-e29b-41d4-a716-446655440001
X-User-Permissions: transaction:read,transaction:write,budget:read,budget:write,report:read,workspace:settings,workspace:members
X-Service-Secret: <gateway_secret>
X-Source: gateway
```

**Financial service receives and uses:**
```java
@PostMapping("/transactions")
@RequiresPermission(Permission.TRANSACTION_WRITE)
public ResponseEntity<TransactionDto> createTransaction(
        @RequestHeader("X-User-Id") UUID userId,           // 550e8400-e29b-41d4-a716-446655440000
        @RequestHeader("X-Workspace-Id") UUID workspaceId, // 660e8400-e29b-41d4-a716-446655440001
        @Valid @RequestBody CreateTransactionRequest request) {
    
    // Transaction automatically scoped to workspace
    Transaction transaction = transactionService.create(request, workspaceId, userId);
    return ResponseEntity.ok(TransactionDto.fromEntity(transaction));
}
```

#### 7.5 Workspace Data Isolation

**All queries automatically scoped to workspace:**
```sql
-- Transactions are isolated per workspace
SELECT * FROM transactions WHERE workspace_id = '660e8400-e29b-41d4-a716-446655440001';

-- Budgets are isolated per workspace
SELECT * FROM budgets WHERE workspace_id = '660e8400-e29b-41d4-a716-446655440001';

-- No cross-workspace data access possible
```

## Implementation Timeline

### Week 1: Database Schema and Simplified Entities
- ✅ Create workspace, permission, role, and membership tables
- ✅ Implement simplified entity classes (Owner/Viewer only)
- ✅ Set up repositories and basic services
- ✅ Create default role creation logic

### Week 2: Enhanced Authentication and JWT
- ✅ Update JWT service for workspace context
- ✅ Enhance gateway authentication flow
- ✅ Implement single workspace context filter
- ✅ Update user service authentication endpoints

### Week 3: Type-Safe Permission Framework and Services
- ✅ Create type-safe permission enums and annotations
- ✅ Build example financial service with workspace scoping
- ✅ Implement Owner/Viewer role system
- ✅ Set up proper workspace isolation

### Week 4: Integration and Testing
- ✅ Configure gateway routes
- ✅ End-to-end testing of workspace isolation
- ✅ Test Owner vs Viewer permission enforcement
- ✅ Documentation and examples

### Week 5: Production Readiness
- ✅ Migration scripts for existing data
- ✅ Performance testing
- ✅ Security audit
- ✅ Team training and documentation

## Key Benefits

1. **Simple Two-Role System**: Easy to understand Owner vs Viewer permissions
2. **Complete Workspace Isolation**: All data automatically scoped to workspace
3. **Type-Safe Permissions**: Compile-time safety with enums
4. **JWT-Based Performance**: No database lookups for permission checks
5. **Industry-Standard Pattern**: Single service for identity management
6. **Family & Business Friendly**: Works for both use cases
7. **Developer Friendly**: Clean annotations and automatic header injection

## Role Capabilities

### Owner Role Permissions:
- ✅ Read all transactions, budgets, reports
- ✅ Create, edit, delete transactions
- ✅ Create, edit, delete budgets
- ✅ Invite/remove workspace members
- ✅ Change workspace settings
- ✅ Switch member roles (Owner ↔ Viewer)

### Viewer Role Permissions:
- ✅ Read all transactions, budgets, reports
- ❌ Cannot create, edit, or delete anything
- ❌ Cannot invite members
- ❌ Cannot change settings
- ❌ Cannot manage roles

## Future Extensions

When you need more granular permissions later, you can easily add:
- **Manager Role**: Can write financial data but not manage members
- **Accountant Role**: Can manage budgets but not transactions
- **Custom Roles**: User-defined permission combinations

The architecture supports this expansion without breaking changes.

## Security Considerations

1. **Workspace Context Validation**: Every service validates workspace ID
2. **Permission Caching**: JWT tokens contain permissions for fast checks
3. **Type Safety**: Enum-based permissions prevent typos and errors
4. **Simple Role Model**: Less complexity = fewer security mistakes
5. **Audit Logging**: All permission checks logged
6. **Cross-Workspace Prevention**: Database queries always filter by workspace_id

## Migration Strategy

1. **Backward Compatibility**: Existing user service functionality preserved
2. **Gradual Rollout**: Enable multi-workspace budgeting feature by feature
3. **Data Migration**: Scripts to assign existing users to default workspace
4. **Fallback Mode**: Option to disable multi-workspace for development

This simplified architecture provides a robust foundation for multi-workspace budgeting with clear, understandable permissions that work for both families and businesses, using modern type-safe practices throughout.