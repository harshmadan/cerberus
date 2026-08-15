# Cerberus Authentication Server

A comprehensive authentication and authorization server built with Spring Boot 3.3.2, featuring JWT-based authentication, role-based access control, refresh token management, and audit logging.

## Features

- **JWT Authentication**: Secure stateless authentication with access tokens (15 min expiration) and refresh tokens
- **User Management**: Registration with email verification, login, logout with token revocation
- **Email Verification**: Users must verify their email address before logging in
- **Password Reset**: Secure forgot password flow with token-based reset
- **OAuth2 Integration**: Google OAuth2 login support
- **Role-Based Access Control (RBAC)**: Users, roles, and permissions hierarchy with fine-grained access control
- **Permission System**: Granular permissions using "resource:action" convention (e.g., `user:read`, `role:manage`)
- **Admin Management API**: Dedicated endpoints for user, role, and permission management
- **Refresh Token System**: Redis-based token storage with reuse detection
- **Audit Logging**: Track authentication events and security-relevant actions
- **Rate Limiting**: Redis-based rate limiting for sensitive endpoints (5 requests per minute per IP)
- **Password Security**: BCrypt hashing with automatic salt generation
- **Method-Level Security**: `@PreAuthorize` annotations for both role-based (`hasRole`) and permission-based (`hasAuthority`) checks
- **API Documentation**: Interactive Swagger/OpenAPI UI at `/swagger-ui.html`
- **Email Testing**: Mailhog integration for email verification and password reset testing
- **Structured API Responses**: Consistent response format with status, message, and timestamp

## Tech Stack

- **Framework**: Spring Boot 3.3.2, Java 17
- **Database**: PostgreSQL 16 (users, roles, permissions, refresh tokens, audit logs)
- **Cache/Session**: Redis 7 (refresh tokens, rate-limit counters)
- **Security**: Spring Security, JWT (jjwt 0.12.5), BCrypt
- **Email**: Spring Mail with Mailhog (dev/testing)
- **Documentation**: SpringDoc OpenAPI 2.5.0
- **Build**: Maven
- **Utilities**: Lombok, Validation, AOP

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Java 17
- Maven (or use the included Maven wrapper)

### Running the Application

1. **Start the infrastructure** (Postgres, Redis, Mailhog):
   ```bash
   docker compose up -d
   ```

2. **Verify containers are healthy**:
   ```bash
   docker compose ps
   ```
   All three services should show "healthy" or "running".

3. **Run the Spring Boot application**:
   ```bash
   ./mvnw spring-boot:run
   ```
   Or with Maven installed:
   ```bash
   mvn spring-boot:run
   ```

4. **Access the application**:
   - API Documentation: http://localhost:8080/swagger-ui.html
   - Mailhog UI: http://localhost:8025
   - Application runs on port 8080

## API Endpoints

### Authentication (`/api/auth`)

- **POST** `/api/auth/register` - Register a new user
  - Body: `{ "email": "string", "password": "string" }`
  - Response: 201 Created (sends verification email)
  - Rate Limited: 5 requests per minute per IP

- **POST** `/api/auth/login` - Login with credentials
  - Body: `{ "email": "string", "password": "string" }`
  - Response: `{ "accessToken": "string", "refreshToken": "string" }`
  - Note: User must have verified their email before logging in
  - Rate Limited: 5 requests per minute per IP

- **POST** `/api/auth/refresh` - Refresh access token
  - Body: `{ "refreshToken": "string" }`
  - Response: `{ "accessToken": "string", "refreshToken": "string" }`

- **POST** `/api/auth/logout` - Logout and revoke refresh token
  - Body: `{ "refreshToken": "string" }`
  - Response: 204 No Content

- **GET** `/api/auth/verify-email` - Verify email address
  - Query: `token=string` (from verification email)
  - Response: 200 OK with success message

- **POST** `/api/auth/forgot-password` - Request password reset
  - Body: `{ "email": "string" }`
  - Response: 200 OK (always succeeds to prevent email enumeration)
  - Rate Limited: 5 requests per minute per IP

- **POST** `/api/auth/reset-password` - Reset password with token
  - Body: `{ "token": "string", "newPassword": "string" }`
  - Response: 204 No Content

- **OAuth2 Login** - Google OAuth2 authentication
  - Start: `/oauth2/authorization/google` (redirects to Google)
  - Callback: `/login/oauth2/code/google` (Google redirects back)
  - Response: `{ "accessToken": "string", "refreshToken": "string" }`

### User Management (`/api/users`)

Protected endpoints requiring JWT authentication (see security configuration).

- **GET** `/api/users/me` - Get current user information
  - Headers: `Authorization: Bearer <accessToken>`
  - Response: `{ "email": "string", "authorities": [...] }`

### Admin Management (`/api/admin`)

Protected endpoints requiring admin role and specific permissions.

- **GET** `/api/admin/users` - List all users (requires `ROLE_ADMIN`)
  - Headers: `Authorization: Bearer <accessToken>`
  - Response: Array of user summaries with ID, email, enabled status, and roles

- **POST** `/api/admin/users/{userId}/roles` - Assign role to user (requires `role:manage` permission)
  - Headers: `Authorization: Bearer <accessToken>`
  - Body: `{ "roleName": "ROLE_ADMIN" }`
  - Response: 204 No Content

- **POST** `/api/admin/permissions` - Create new permission (requires `ROLE_ADMIN`)
  - Headers: `Authorization: Bearer <accessToken>`
  - Body: `{ "name": "resource:action" }`
  - Response: 201 Created

- **POST** `/api/admin/roles/{roleId}/permissions` - Assign permission to role (requires `role:manage` permission)
  - Headers: `Authorization: Bearer <accessToken>`
  - Body: `{ "permissionName": "user:delete" }`
  - Response: 204 No Content

- **POST** `/api/admin/users/{userId}/deleteRole` - Remove role from user (requires `role:manage` permission)
  - Headers: `Authorization: Bearer <accessToken>`
  - Body: `{ "roleName": "ROLE_ADMIN" }`
  - Response: `{ "status": 200, "message": "Role deleted successfully", "timestamp": "datetime" }`

- **GET** `/api/admin/auditLogs` - Retrieve audit log entries (requires `role:read` permission)
  - Headers: `Authorization: Bearer <accessToken>`
  - Response: Array of audit log entries with timestamp, action, user, and details

## Database Schema

The application automatically creates the following tables on startup:

- **users** - User accounts with credentials
- **roles** - Role definitions (e.g., USER, ADMIN)
- **permissions** - Granular permissions
- **refresh_tokens** - Token storage in Redis
- **audit_logs** - Security event tracking

### Default Data Seeding

On startup, the application automatically seeds:

- **Roles**: `ROLE_USER`, `ROLE_ADMIN`
- **Permissions**: `user:read`, `user:write`, `user:delete`, `role:manage` (assigned to ROLE_ADMIN)
- **Admin Account**: `admin@cerberus.dev` with password `AdminPass123!` (dev-only convenience)
  - Note: The admin account is created as enabled by default for convenience in development
  - Regular users must verify their email before logging in

### Direct Database Access

Connect to PostgreSQL directly:
```bash
psql -h localhost -U cerberus -d cerberus
```
Password: `cerberus_dev_password`

## Configuration

### Application Configuration (`application.yml`)

Key configuration settings:

- **Server Port**: 8080
- **Database**: PostgreSQL on localhost:5432
- **Redis**: localhost:6379
- **JWT Secret**: Configured in application.yml (change for production)
- **Access Token Expiration**: 15 minutes
- **Mail**: Mailhog on localhost:1025

### Security Configuration

- Public endpoints: `/api/auth/**`, `/swagger-ui/**`, `/v3/api-docs/**`, `/oauth2/**`, `/login/**`
- All other endpoints require JWT authentication
- Email verification required for new user registrations (except seeded admin)
- Method-level security with `@PreAuthorize` annotations for fine-grained access control
- Role-based checks: `@PreAuthorize("hasRole('ADMIN')")`
- Permission-based checks: `@PreAuthorize("hasAuthority('user:delete')")`
- Stateless session management
- BCrypt password encoding
- CSRF disabled (stateless JWT architecture)
- Custom error responses: 401 for authentication failures, 403 for authorization failures
- OAuth2 support for Google login (requires environment variables: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`)
- Rate limiting: Applied to `/api/auth/register`, `/api/auth/login`, and `/api/auth/forgot-password` endpoints
  - 5 requests per minute per IP address
  - Implemented using Redis for distributed counting
  - Returns HTTP 429 (Too Many Requests) when limit exceeded
  - Supports X-Forwarded-For header for proxy deployments

## Development

### Project Structure

```
src/main/java/com/cerberus/auth/
├── config/           # Security, exception handling, data seeding
├── controller/       # REST endpoints
├── dto/             # Request/response objects
├── entity/          # JPA entities
├── repository/      # Data access layer
├── security/        # JWT filters, services, user details
└── service/         # Business logic
```

### Building

```bash
./mvnw clean install
```

### Testing

```bash
./mvnw test
```
