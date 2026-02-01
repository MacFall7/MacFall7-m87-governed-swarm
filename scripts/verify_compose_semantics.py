#!/usr/bin/env python3
"""
Compose Semantic Validator

Verifies docker-compose.yml has required structure for Phase 2.
YAML syntax is not enough - this checks semantic requirements.

Required for Phase 2:
- services.postgres exists with healthcheck
- services.api.environment.DATABASE_URL exists
- services.api.depends_on.postgres.condition == service_healthy
- volumes.postgres_data exists
"""

import sys
import yaml
from pathlib import Path


def load_compose(path: str) -> dict:
    """Load and parse docker-compose.yml."""
    with open(path) as f:
        return yaml.safe_load(f)


def check_postgres_service(compose: dict) -> list:
    """Check Postgres service requirements."""
    errors = []
    services = compose.get("services", {})

    if "postgres" not in services:
        errors.append("MISSING: services.postgres")
        return errors

    pg = services["postgres"]

    if "image" not in pg:
        errors.append("MISSING: services.postgres.image")

    if "healthcheck" not in pg:
        errors.append("MISSING: services.postgres.healthcheck")
    else:
        hc = pg["healthcheck"]
        if "test" not in hc:
            errors.append("MISSING: services.postgres.healthcheck.test")

    env = pg.get("environment", [])
    env_keys = set()
    if isinstance(env, list):
        for item in env:
            if isinstance(item, str) and "=" in item:
                env_keys.add(item.split("=")[0])
            elif isinstance(item, str):
                env_keys.add(item)
    elif isinstance(env, dict):
        env_keys = set(env.keys())

    required_env = {"POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB"}
    missing_env = required_env - env_keys
    for key in missing_env:
        errors.append(f"MISSING: services.postgres.environment.{key}")

    return errors


def check_api_service(compose: dict) -> list:
    """Check API service requirements for Phase 2."""
    errors = []
    services = compose.get("services", {})

    if "api" not in services:
        errors.append("MISSING: services.api")
        return errors

    api = services["api"]

    # Check DATABASE_URL in environment
    env = api.get("environment", [])
    has_database_url = False

    if isinstance(env, list):
        for item in env:
            if isinstance(item, str) and item.startswith("DATABASE_URL"):
                has_database_url = True
                break
    elif isinstance(env, dict):
        has_database_url = "DATABASE_URL" in env

    if not has_database_url:
        errors.append("MISSING: services.api.environment.DATABASE_URL")

    # Check depends_on.postgres
    depends_on = api.get("depends_on", {})

    if "postgres" not in depends_on:
        errors.append("MISSING: services.api.depends_on.postgres")
    else:
        pg_dep = depends_on["postgres"]
        if isinstance(pg_dep, dict):
            condition = pg_dep.get("condition")
            if condition != "service_healthy":
                errors.append(
                    f"WRONG: services.api.depends_on.postgres.condition = '{condition}' "
                    f"(expected: 'service_healthy')"
                )
        else:
            errors.append(
                "WRONG: services.api.depends_on.postgres should have condition: service_healthy"
            )

    return errors


def check_volumes(compose: dict) -> list:
    """Check volume definitions."""
    errors = []
    volumes = compose.get("volumes", {})

    if "postgres_data" not in volumes:
        errors.append("MISSING: volumes.postgres_data")

    return errors


def main():
    compose_path = Path("infra/docker-compose.yml")

    if not compose_path.exists():
        print(f"ERROR: {compose_path} not found")
        sys.exit(1)

    try:
        compose = load_compose(compose_path)
    except yaml.YAMLError as e:
        print(f"YAML_ERROR: {e}")
        sys.exit(1)

    all_errors = []
    all_errors.extend(check_postgres_service(compose))
    all_errors.extend(check_api_service(compose))
    all_errors.extend(check_volumes(compose))

    if all_errors:
        print("COMPOSE SEMANTIC VALIDATION FAILED")
        print("=" * 40)
        for error in all_errors:
            print(f"  {error}")
        print("")
        print(f"Total errors: {len(all_errors)}")
        sys.exit(1)
    else:
        print("COMPOSE SEMANTIC VALIDATION PASSED")
        print("  [x] services.postgres with healthcheck")
        print("  [x] services.api.environment.DATABASE_URL")
        print("  [x] services.api.depends_on.postgres.condition = service_healthy")
        print("  [x] volumes.postgres_data")
        sys.exit(0)


if __name__ == "__main__":
    main()
