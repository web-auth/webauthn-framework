<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Authentication\Exception;

use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Throwable;
use Webauthn\AuthenticatorResponse;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Authentication failure raised by {@see \Webauthn\Bundle\Security\Authentication\WebauthnBadgeListener}
 * when an assertion or attestation ceremony failed to validate.
 *
 * Unlike a generic `AuthenticationException`, this one carries the deserialized
 * pieces of the ceremony so a custom `Authenticator::onAuthenticationFailure()`
 * can build a contextual response (e.g. a WebAuthn L3 §5.1.10 `signalUnknownCredential`
 * payload to drop the stale passkey from the platform's UI).
 *
 * Pre-deserialization failures (malformed JSON body, missing stored options) keep
 * the existing "silent fail" behaviour: the badge stays unresolved and Symfony's
 * pipeline reports a generic auth failure. This class is only raised once the
 * listener has decided the badge is a real WebAuthn ceremony but its validation
 * step rejected it.
 */
final class WebauthnAuthenticationFailureException extends AuthenticationException
{
    public function __construct(
        string $message,
        public readonly ?PublicKeyCredential $publicKeyCredential = null,
        public readonly ?AuthenticatorResponse $authenticatorResponse = null,
        public readonly ?PublicKeyCredentialOptions $publicKeyCredentialOptions = null,
        public readonly ?PublicKeyCredentialUserEntity $userEntity = null,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    public function getMessageKey(): string
    {
        return 'Webauthn authentication failed.';
    }
}
