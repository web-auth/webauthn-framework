# Migration from PublicKeyCredentialSource to CredentialRecord

## Overview

As of version 5.3, `PublicKeyCredentialSource` is deprecated in favor of `CredentialRecord`, which follows the WebAuthn Level 3 specification. This guide will help you migrate your application smoothly.

## Key Changes

- `PublicKeyCredentialSource` is now deprecated but will continue to work until version 6.0
- `CredentialRecord` is the new recommended class for storing credentials
- Both classes can coexist in your application during the migration period
- **Both classes are independent** - they have the same structure but do not extend each other
- All framework components support both types via union type declarations

## Repository Migration

### Option 1: Update Interface (Recommended)

Update your repository interface from `PublicKeyCredentialSourceRepositoryInterface` to `CredentialRecordRepositoryInterface`:

```php
// Before (deprecated)
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;

class MyCredentialRepository implements PublicKeyCredentialSourceRepositoryInterface
{
    // ...
}

// After
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;

class MyCredentialRepository implements CredentialRecordRepositoryInterface
{
    // No other changes needed - methods remain the same!
}
```

### Option 2: Support Both Interfaces (For Gradual Migration)

Your repository can implement both interfaces during the transition:

```php
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;

class MyCredentialRepository implements
    CredentialRecordRepositoryInterface,
    PublicKeyCredentialSourceRepositoryInterface
{
    // Both interfaces have the same methods, so no duplication needed
}
```

## Method Signatures

All repository methods now accept union types for maximum compatibility:

```php
public function findOneByCredentialId(string $publicKeyCredentialId): CredentialRecord|PublicKeyCredentialSource|null
{
    // Your implementation
}

public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
{
    // Returns array<CredentialRecord|PublicKeyCredentialSource>
}

public function saveCredentialSource(CredentialRecord|PublicKeyCredentialSource $credentialRecord): void
{
    // Accepts both types
}
```

## Entity Migration

### Using Doctrine

If you're using Doctrine, your entity can extend either class:

```php
use Doctrine\ORM\Mapping as ORM;
use Webauthn\CredentialRecord;

#[ORM\Entity]
#[ORM\Table(name: 'credentials')]
class MyCredential extends CredentialRecord
{
    #[ORM\Id]
    #[ORM\Column(type: 'integer')]
    #[ORM\GeneratedValue]
    private int $id;

    // Your custom fields...
}
```

Both `CredentialRecord` and `PublicKeyCredentialSource` have identical Doctrine mappings, so migration is seamless.

### Converting Existing Data

If you need to convert between the two types, use the `CredentialRecordConverter` utility:

```php
use Webauthn\Util\CredentialRecordConverter;

// Convert PublicKeyCredentialSource to CredentialRecord
$credentialRecord = CredentialRecordConverter::toCredentialRecord($publicKeyCredentialSource);

// Convert CredentialRecord to PublicKeyCredentialSource (if needed for backward compatibility)
$publicKeyCredentialSource = CredentialRecordConverter::toPublicKeyCredentialSource($credentialRecord);

// Convert arrays
$credentialRecords = CredentialRecordConverter::toCredentialRecords($publicKeyCredentialSources);
$publicKeyCredentialSources = CredentialRecordConverter::toPublicKeyCredentialSources($credentialRecords);
```

## Database Migration

The database schema remains the same! Both classes use identical field mappings:

- `publicKeyCredentialId` (base64, unique, length 250)
- `type` (string)
- `transports` (json)
- `attestationType` (string)
- `trustPath` (trust_path type)
- `aaguid` (aaguid type, length 36)
- `credentialPublicKey` (base64)
- `userHandle` (string)
- `counter` (integer)
- `otherUI` (json, nullable)
- `backupEligible` (boolean, nullable)
- `backupStatus` (boolean, nullable)
- `uvInitialized` (boolean, nullable)

**No database migration is required!** Simply update your entity class:

```php
// Before
class MyCredential extends PublicKeyCredentialSource { }

// After
class MyCredential extends CredentialRecord { }
```

## Testing Both Types

All validators, authenticators, and ceremony steps support both types:

```php
// Works with CredentialRecord
$validator->check(
    $credentialRecord,  // CredentialRecord
    $response,
    $options,
    $host,
    $userHandle
);

// Works with PublicKeyCredentialSource
$validator->check(
    $publicKeyCredentialSource,  // PublicKeyCredentialSource
    $response,
    $options,
    $host,
    $userHandle
);
```

## Migration Checklist

- [ ] Update repository interfaces to `CredentialRecordRepositoryInterface`
- [ ] Update entity classes to extend `CredentialRecord` instead of `PublicKeyCredentialSource`
- [ ] Update type hints in your code from `PublicKeyCredentialSource` to `CredentialRecord` (or use union types)
- [ ] Test your application thoroughly
- [ ] Remove any usage of deprecated methods/classes before upgrading to version 6.0

## Backward Compatibility

During the transition period (until version 6.0):

- Both classes work seamlessly together
- All framework components accept both types via union types
- Deprecation warnings help identify areas to update
- No breaking changes in your database or API

## Example: Complete Migration

```php
// Before (v5.2 and earlier)
use Webauthn\PublicKeyCredentialSource;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;

class CredentialRepository implements PublicKeyCredentialSourceRepositoryInterface
{
    public function findOneByCredentialId(string $id): ?PublicKeyCredentialSource
    {
        return $this->entityManager
            ->getRepository(MyCredential::class)
            ->findOneBy(['publicKeyCredentialId' => $id]);
    }
}

// After (v5.3+)
use Webauthn\CredentialRecord;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;

class CredentialRepository implements CredentialRecordRepositoryInterface
{
    public function findOneByCredentialId(string $id): CredentialRecord|PublicKeyCredentialSource|null
    {
        return $this->entityManager
            ->getRepository(MyCredential::class)
            ->findOneBy(['publicKeyCredentialId' => $id]);
    }
}
```

## Support

For questions or issues during migration:
- Check the [GitHub Issues](https://github.com/web-auth/webauthn-framework/issues)
- Review the [test examples](../tests) for implementation patterns
- Consult the [WebAuthn Level 3 spec](https://www.w3.org/TR/webauthn-3/#credential-record)
