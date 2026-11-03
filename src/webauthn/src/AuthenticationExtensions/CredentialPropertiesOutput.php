<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use function is_array;
use function is_bool;
use function is_string;
use Webauthn\Exception\AuthenticationExtensionException;

/**
 * W3C WebAuthn L3 §10.1.3: typed view of the `credProps` client extension
 * output. Exposes both `rk` (whether the credential is a discoverable
 * credential / passkey) and `authenticatorDisplayName` (a human-friendly
 * name suggested by the authenticator, added in Level 3).
 *
 * Use {@see fromExtensions()} or {@see fromExtension()} to materialise the
 * value object from the raw extension bag returned by the client.
 */
final readonly class CredentialPropertiesOutput
{
    public function __construct(
        public ?bool $rk,
        public ?string $authenticatorDisplayName,
    ) {
    }

    public static function create(?bool $rk, ?string $authenticatorDisplayName = null): self
    {
        return new self($rk, $authenticatorDisplayName);
    }

    public static function fromExtensions(AuthenticationExtensions $extensions): ?self
    {
        if (! $extensions->has('credProps')) {
            return null;
        }

        return self::fromExtension($extensions->get('credProps'));
    }

    public static function fromExtension(AuthenticationExtension $extension): self
    {
        $extension->name === 'credProps' || throw AuthenticationExtensionException::create(
            'The extension is not a "credProps" extension.'
        );

        $value = $extension->value;
        if ($value === null) {
            return new self(null, null);
        }

        is_array($value) || throw AuthenticationExtensionException::create(
            'The "credProps" extension output must be an object/array.'
        );

        $rk = $value['rk'] ?? null;
        $rk === null || is_bool($rk) || throw AuthenticationExtensionException::create(
            'The "credProps.rk" output must be a boolean.'
        );

        $authenticatorDisplayName = $value['authenticatorDisplayName'] ?? null;
        $authenticatorDisplayName === null || is_string(
            $authenticatorDisplayName
        ) || throw AuthenticationExtensionException::create(
            'The "credProps.authenticatorDisplayName" output must be a string.'
        );

        return new self($rk, $authenticatorDisplayName);
    }
}
