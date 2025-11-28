<?php

declare(strict_types=1);

namespace Webauthn\CeremonyStep;

use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CredentialRecord;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use function trigger_deprecation;

final class CheckUserVerification implements CeremonyStep
{
    public function process(
        CredentialRecord|PublicKeyCredentialSource $credentialRecord,
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
        $userVerification = $publicKeyCredentialOptions instanceof PublicKeyCredentialRequestOptions ? $publicKeyCredentialOptions->userVerification : $publicKeyCredentialOptions->authenticatorSelection?->userVerification;
        if ($userVerification !== AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED) {
            return;
        }
        $authData = $authenticatorResponse instanceof AuthenticatorAssertionResponse ? $authenticatorResponse->authenticatorData : $authenticatorResponse->attestationObject->authData;
        $authData->isUserVerified() || throw AuthenticatorResponseVerificationException::create(
            'User authentication required.'
        );
    }
}
