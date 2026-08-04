# Cerberus — Day 1

## What this is
Infrastructure + data model only. No auth logic yet — that starts Day 2.

## How to run it

1. Start the infrastructure:
   ```
   docker compose up -d
   ```
   This brings up Postgres, Redis, and Mailhog in the background.

2. Check they're healthy:
   ```
   docker compose ps
   ```
   All three should say "healthy" or "running".

3. Run the Spring Boot app (from the project root):
   ```
   ./mvnw spring-boot:run
   ```
   (If you don't have the Maven wrapper yet, run `mvn spring-boot:run` with
   Maven installed, or import the project into IntelliJ and run it there.)

4. Visit http://localhost:8080/swagger-ui.html — you should see an empty
   Swagger page (no endpoints yet, that's expected). If this loads without
   errors, Spring Boot successfully connected to Postgres and Redis.

5. Visit http://localhost:8025 — Mailhog's inbox UI. Empty for now, but
   this is where verification emails will land on Day 5.

## What "Day 1 done" actually means
- `docker compose ps` shows three healthy containers
- The app boots with zero errors in the console
- Hibernate's logs (visible because `show-sql: true`) show it creating
  the `users`, `roles`, `permissions`, `refresh_tokens`, and `audit_logs`
  tables automatically on startup
- You can connect to Postgres directly (`psql -h localhost -U cerberus -d cerberus`,
  password `cerberus_dev_password`) and see those five empty tables

If all of that is true, the foundation is solid and Day 2 (actual login/JWT
logic) has something real to build on.
