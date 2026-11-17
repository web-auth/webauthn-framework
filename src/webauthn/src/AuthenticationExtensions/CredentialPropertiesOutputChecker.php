<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use function is_array;
use function is_bool;
use function is_string;
use Webauthn\Exception\AuthenticatorResponseVerificationException;

/**
 * Validates the structure of the `credProps` client extension OUTPUT.
 *
 * Per W3C WebAuthn L3 §10.1.3 the output is a {@code CredentialPropertiesOutput}
 * dictionary that may carry:
 *  - `rk`: boolean — whether the credential is a discoverable credential
 *    (passkey).
 *  - `authenticatorDisplayName`: string — a human-readable label suggested
 *    by the authenticator for the credential (added in Level 3).
 *
 * Both members are optional. The user agent may omit the extension output
 * entirely if it does not support `credProps`; that is allowed and the
 * checker stays silent in that case. When the output IS returned, this
 * checker enforces that each present field has the right type so callers
 * can rely on {@see CredentialPropertiesOutput} for typed access.
 */
final readonly class CredentialPropertiesOutputChecker implements ExtensionOutputChecker
{
    public function check(AuthenticationExtensions $inputs, AuthenticationExtensions $outputs): void
    {
        if (! $inputs->has('credProps')) {
            return;
        }

        if (! $outputs->has('credProps')) {
            return;
        }

        $rawOutput = $outputs->get('credProps')
            ->value;
        if ($rawOutput === null) {
            return;
        }

        if (! is_array($rawOutput)) {
            throw AuthenticatorResponseVerificationException::create('Invalid credProps extension output format.');
        }

        if (isset($rawOutput['rk']) && ! is_bool($rawOutput['rk'])) {
            throw AuthenticatorResponseVerificationException::create(
                'The credProps extension output "rk" field must be a boolean.',
            );
        }

        if (isset($rawOutput['authenticatorDisplayName']) && ! is_string($rawOutput['authenticatorDisplayName'])) {
            throw AuthenticatorResponseVerificationException::create(
                'The credProps extension output "authenticatorDisplayName" field must be a string.',
            );
        }
    }
}
