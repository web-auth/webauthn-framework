# Deprecation of the Reserved-For-Future-Use accessors

## Overview

The `RFU1` and `RFU2` bits of the authenticator data flags are reserved by the WebAuthn specification and SHALL be set
to zero by authenticators. Reading them back brings no value to a Relying Party: a compliant authenticator always
yields `0`, and a non-compliant one reports a value the application cannot act upon.

As of version 5.4.0, the accessors exposing these bits are deprecated. They will be removed in 6.0.0.

## What is deprecated

| Deprecated since 5.4.0                                              | Removed in 6.0.0 |
|---------------------------------------------------------------------|------------------|
| `Webauthn\AuthenticatorData::getReservedForFutureUse1()`              | yes              |
| `Webauthn\AuthenticatorData::getReservedForFutureUse2()`              | yes              |
| `Webauthn\Bundle\Security\Authentication\Token\WebauthnToken::getReservedForFutureUse1()` | yes |
| `Webauthn\Bundle\Security\Authentication\Token\WebauthnToken::getReservedForFutureUse2()` | yes |
| The `$reservedForFutureUse1` and `$reservedForFutureUse2` arguments of the `WebauthnToken` constructor | yes |

Nothing changes in 5.4: the constructor signature is unchanged, the values are still stored, and the getters still
return them. Only a deprecation notice is emitted when a getter is called.

## How to migrate

Remove any call to these accessors. There is no replacement, as the values carry no information.

```php
// Before
if ($authenticatorData->getReservedForFutureUse1() !== 0) {
    // Unreachable with a compliant authenticator
}

// After
// Nothing: drop the check entirely.
```

If you need the raw flags byte for your own inspection, it remains available through the public `flags` property:

```php
$flags = ord($authenticatorData->flags);
```

## What changes in 6.0.0

The two accessors are removed from `AuthenticatorData` and from `WebauthnToken`, and the two arguments are dropped from
the `WebauthnToken` constructor as well as from its `__serialize()` and `__unserialize()` methods.

Because the serialized payload of the token loses two entries, sessions created by a 5.x application cannot be
unserialized by a 6.0 application. Plan to invalidate the existing sessions when you upgrade.
