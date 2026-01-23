<?php

declare(strict_types=1);

namespace Webauthn\CeremonyStep;

use function trigger_deprecation;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\CredentialRecord;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;

/**
 * Conditional check for user presence
 *
 * This step allows user presence to be false for Conditional Create scenarios
 * where mediation: 'conditional' is used (e.g., auto-register after password login).
 *
 * @see https://github.com/w3c/webauthn/wiki/Explainer:-Conditional-Create
 */
final readonly class CheckUserWasPresent implements CeremonyStep
{
    public function __construct(
        private bool $requireUserPresence = true
    ) {
    }

    public function process(
        CredentialRecord $credentialRecord,
        AuthenticatorAssertionResponse|AuthenticatorAttestationResponse $authenticatorResponse,
        PublicKeyCredentialRequestOptions|PublicKeyCredentialCreationOptions $publicKeyCredentialOptions,
        ?string $userHandle,
        string $host
    ): void {
        if ($credentialRecord instanceof PublicKeyCredentialSource) {
            trigger_deprecation(
                'web-auth/webauthn-lib',
                '5.3',
                'Passing a PublicKeyCredentialSource to "%s::process()" is deprecated, pass a CredentialRecord instead.',
                self::class
            );
        }
        if (! $this->requireUserPresence) {
            return;
        }

        $authData = $authenticatorResponse instanceof AuthenticatorAssertionResponse
            ? $authenticatorResponse->authenticatorData
            : $authenticatorResponse->attestationObject->authData;

        $authData->isUserPresent() || throw AuthenticatorResponseVerificationException::create(
            'User was not present'
        );
    }
}
