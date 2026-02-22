# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a FIDO2/WebAuthn framework for PHP and Symfony, implementing the W3C WebAuthn specification. The repository contains three complementary modules organized as a monorepo:

- **webauthn-lib** (`src/webauthn/`) - Core PHP library with no framework dependencies
- **webauthn-symfony-bundle** (`src/symfony/`) - Symfony integration providing controllers, services, and configuration
- **webauthn-stimulus** (`src/stimulus/`) - Frontend Stimulus.js integration for client-side WebAuthn interactions

## Development Commands

### PHP Development (via Castor)

The project uses Castor for task automation. Commands use the `castor` CLI:

```bash
# Run all tests with coverage
castor phpunit

# Static analysis
castor phpstan
castor phpstan-baseline  # Generate new baseline

# Code style
castor ecs              # Check coding standards
castor ecs-fix          # Auto-fix coding standards

# Refactoring
castor rector           # Check refactoring suggestions
castor rector-fix       # Apply refactoring

# Architecture validation
castor deptrac          # Check dependency layers

# Syntax checking
castor lint

# Mutation testing
castor infect

# License compliance
castor check-licenses

# Prepare code for PR (fixes style, applies Rector, runs analysis)
castor prepare-pr
```

### JavaScript Development

```bash
# Run all JavaScript tests
npm test

# Linting
npm run lint            # Check linting
npm run lint:fix        # Auto-fix linting issues

# Code formatting
npm run format          # Check formatting
npm run format:fix      # Auto-fix formatting
```

### Running Single Tests

PHPUnit tests are located in:
- `tests/framework/` - Core library tests
- `tests/library/` - Additional library tests
- `tests/symfony/functional/` - Symfony bundle functional tests
- `tests/MDS/` - Metadata Service tests

To run specific tests, use the standard PHPUnit filter syntax via the vendor binary:
```bash
vendor/bin/phpunit --filter=TestClassName tests/
vendor/bin/phpunit tests/framework/SomeSpecificTest.php
```

## Architecture Overview

### Ceremony Steps Pattern

The core validation logic uses a "ceremony steps" pattern where both registration and authentication ceremonies are composed of discrete, reusable validation steps:

- Steps are located in `src/webauthn/src/CeremonyStep/`
- Each step implements the `CeremonyStep` interface
- Steps are orchestrated by `CeremonyStepManager` (built via `CeremonyStepManagerFactory`)
- Registration ceremony includes ~14 steps (CheckOrigin, CheckChallenge, CheckRelyingPartyIdHash, etc.)
- Authentication ceremony includes ~12 steps (CheckSignature, CheckCounter, CheckUserHandle, etc.)

### Main Validators

Two primary validators orchestrate the ceremony flows:

- `AuthenticatorAttestationResponseValidator` - Handles registration/attestation
- `AuthenticatorAssertionResponseValidator` - Handles authentication/assertion

Both validators:
- Use `CeremonyStepManager` to run validation steps
- Support PSR-14 event dispatching for extensibility
- Support PSR-3 logging
- Update credential records with final authenticator data after successful validation

### Repository Pattern

Data persistence is abstracted through repository interfaces:

- `CredentialRecordRepositoryInterface` - Query credentials by user or credential ID
  - Optional `CanSaveCredentialRecord` interface for persistence operations
- `PublicKeyCredentialUserEntityRepositoryInterface` - User lookup by username or user handle
- Implementations: `DoctrineCredentialSourceRepository` (Doctrine), `DummyCredentialRecordRepository` (testing)

### Core Data Models

Key entities that represent WebAuthn protocol data:

**Options (sent to client):**
- `PublicKeyCredentialCreationOptions` - Registration ceremony options
- `PublicKeyCredentialRequestOptions` - Authentication ceremony options

**Responses (received from client):**
- `AuthenticatorAttestationResponse` - Registration response with attestationObject
- `AuthenticatorAssertionResponse` - Authentication response with signature

**Stored Credentials:**
- `CredentialRecord` - Server-side representation of a credential (credential ID, public key, counter, backup status, etc.)
- `PublicKeyCredentialUserEntity` - User information
- `PublicKeyCredentialRpEntity` - Relying Party information

**Supporting Data:**
- `CollectedClientData` - Parsed clientDataJSON (challenge, origin, type)
- `AuthenticatorData` - Parsed authenticator data (RP ID hash, flags, counter, extensions)
- `AttestationObject` - Contains attestation statement and authenticator data

### Ceremony Flows

**Registration (Attestation):**
1. Client calls `/attestation/request` → server generates `PublicKeyCredentialCreationOptions`
2. Options stored in session/cache, returned to client
3. Client uses WebAuthn API to create credential
4. Client posts response to `/attestation/response`
5. Server validates via `AuthenticatorAttestationResponseValidator.check()` using ceremony steps
6. If valid, credential persisted via repository

**Authentication (Assertion):**
1. Client calls `/assertion/request` → server generates `PublicKeyCredentialRequestOptions`
2. Options stored in session/cache, returned to client
3. Client uses WebAuthn API to get credential
4. Client posts response to `/assertion/response`
5. Server validates via `AuthenticatorAssertionResponseValidator.check()` using ceremony steps
6. If valid, credential record updated with new counter and backup status

### Symfony Bundle Integration

Located in `src/symfony/`:

**Controllers:**
- `AttestationRequestController`, `AttestationResponseController` - Handle registration
- `AssertionRequestController`, `AssertionResponseController` - Handle authentication
- Controllers use factory pattern (`AttestationControllerFactory`, `AssertionControllerFactory`)

**Configuration:**
- Service definitions in `src/symfony/src/Resources/config/`
- Doctrine mappings in `src/symfony/src/Resources/config/doctrine-mapping/`
- Bundle configuration via `Configuration.php`

**Security Integration:**
- `WebauthnAuthenticator` - Symfony security authenticator
- `WebauthnToken` - Authentication token
- Event system for security events

### Options Builders & Handlers

**Options Building:**
- `PublicKeyCredentialCreationOptionsBuilder` - Interface for building creation options
- `ProfileBasedCreationOptionsBuilder` - Profile-driven implementation
- `PublicKeyCredentialCreationOptionsFactory` - Factory with configured settings

**Success/Failure Handlers:**
- Provide extensible hooks for custom post-validation logic
- `SuccessHandler`/`FailureHandler` interfaces with default implementations
- Used by controllers to handle ceremony outcomes

### Recent Architectural Changes

The codebase recently underwent a significant refactoring (visible in recent commits):
- `PublicKeyCredentialSource` renamed to `CredentialRecord`
- `PublicKeyCredentialSourceRepository` renamed to `CredentialRecordRepository`
- This improves clarity about what the entity represents (a record of a credential, not the credential itself)

## PHP Requirements

- PHP >= 8.2
- Extensions: json, openssl
- Symfony 6.4+ or 7.0+

## Testing Philosophy

- Tests are in `tests/` directory with subdirectories for each module
- PHPUnit configuration at `.ci-tools/phpunit.xml.dist`
- Mutation testing via Infection for quality assurance
- Functional tests for Symfony bundle integration
- JavaScript tests using Jest

## CI/CD Pipeline

GitHub Actions workflow (`.github/workflows/ci.yml`) runs:
1. Pre-checks (file permissions, ASCII characters)
2. PHPStan (static analysis)
3. ECS (coding standards)
4. Rector (refactoring checks)
5. Composer validation
6. Syntax checking
7. License compliance
8. Deptrac (architecture validation)
9. PHPUnit tests (PHP 8.2, 8.3, 8.4)
10. JavaScript lint, format, and tests
11. Mutation testing (on release branches)

## Documentation

Full documentation available at: https://webauthn-doc.spomky-labs.com/

## Important Notes

- Main branch for PRs: `5.3.x` (or current version branch, not `main`)
- This is a monorepo that replaces separate packages via `composer.json` `replace` section
- Security vulnerabilities should be reported via GitHub Security Advisory, not public issues
- Recent refactoring renamed `PublicKeyCredentialSource` to `CredentialRecord` - be aware when working with older code or documentation
