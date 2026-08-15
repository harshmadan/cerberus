#!/usr/bin/env bash
# Smoke test: exercises the whole running stack end-to-end.
# Run after `docker compose up --build -d`, once all containers are healthy.
#
# This is NOT a substitute for a real automated test suite (Testcontainers
# would be the proper next step -- spinning up throwaway Postgres/Redis
# per test run, fully isolated). This is the more honest middle ground for
# where the project is today: a script that proves a freshly started
# instance actually works, the way you'd sanity-check a real deployment.

set -e
BASE_URL="http://localhost:8080"
EMAIL="smoketest-$(date +%s)@cerberus.dev"
PASSWORD="password123"

echo "== 1. Register =="
curl -s -o /dev/null -w "%{http_code}\n" -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"

echo "== 2. Login before verification (expect 403) =="
curl -s -o /dev/null -w "%{http_code}\n" -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"

echo "== 3. Admin login =="
ADMIN_TOKEN=$(curl -s -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@cerberus.dev","password":"AdminPass123!"}' | grep -o '"accessToken":"[^"]*' | cut -d'"' -f4)

if [ -z "$ADMIN_TOKEN" ]; then
  echo "FAILED to get admin token -- is the app up and DataSeeder working?"
  exit 1
fi
echo "Got admin token."

echo "== 4. Protected endpoint without token (expect 401) =="
curl -s -o /dev/null -w "%{http_code}\n" "$BASE_URL/api/users/me"

echo "== 5. Protected endpoint WITH admin token (expect 200) =="
curl -s -o /dev/null -w "%{http_code}\n" "$BASE_URL/api/users/me" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

echo "== 6. Non-admin hitting admin endpoint (expect 403) =="
curl -s -o /dev/null -w "%{http_code}\n" "$BASE_URL/api/admin/users"

echo "== 7. Admin listing users (expect 200) =="
curl -s -o /dev/null -w "%{http_code}\n" "$BASE_URL/api/admin/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

echo "== 8. Rate limiting -- 6 rapid bad logins, last one should be 429 =="
for i in 1 2 3 4 5 6; do
  curl -s -o /dev/null -w "attempt $i: %{http_code}\n" -X POST "$BASE_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"nonexistent@cerberus.dev","password":"wrong"}'
done

echo "== Smoke test complete. Review the codes above against the expectations in each step. =="
