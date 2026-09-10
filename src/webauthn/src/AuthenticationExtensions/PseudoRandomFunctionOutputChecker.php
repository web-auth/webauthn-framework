<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use Webauthn\Exception\AuthenticatorResponseVerificationException;

/**
 * Rejects a `prf` entry found in the AUTHENTICATOR extension outputs.
 *
 * W3C WebAuthn Level 3 states that authenticator extension outputs MUST NOT contain
 * cleartext PRF outputs. The reason is structural: the authenticator data is signed,
 * so the client cannot strip anything from it before the credential is sent to the
 * relying party server. Any PRF material placed there would leave the client, which
 * defeats the whole point of the extension for the use cases it exists for, such as
 * deriving encryption keys that the server must never hold.
 *
 * Conforming implementations never produce such an output. An authenticator serving
 * PRF through the CTAP `hmac-secret` extension does add an authenticator extension
 * output, but under the `hmac-secret` identifier and encrypted for the client, and
 * an authenticator serving PRF through any other interface exchanges the results
 * outside of the authenticator data entirely. A `prf` key showing up in the
 * authenticator extension outputs therefore signals a broken or hostile
 * authenticator, and the value it carries must not be treated as key material.
 *
 * This checker is NOT registered by default: turning a previously accepted ceremony
 * into a hard failure is a behavioural change that does not belong in a minor
 * release. Relying parties that want the requirement enforced can opt in:
 *
 * ```php
 * $handler = ExtensionOutputCheckerHandler::create();
 * $handler->add(new PseudoRandomFunctionOutputChecker());
 * ```
 *
 * In a Symfony application, registering the service is enough, the bundle
 * autoconfigures every {@see ExtensionOutputChecker} into the handler:
 *
 * ```yaml
 * services:
 *     Webauthn\AuthenticationExtensions\PseudoRandomFunctionOutputChecker: ~
 * ```
 *
 * @see https://www.w3.org/TR/webauthn-3/#prf-extension
 */
final readonly class PseudoRandomFunctionOutputChecker implements ExtensionOutputChecker
{
    public function check(AuthenticationExtensions $inputs, AuthenticationExtensions $outputs): void
    {
        if (! $outputs->has('prf')) {
            return;
        }

        throw AuthenticatorResponseVerificationException::create(
            'The authenticator extension outputs must not contain a "prf" entry. PRF results are client-side only and must never reach the relying party server.',
        );
    }
}
