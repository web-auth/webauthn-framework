<?php

declare(strict_types=1);

namespace Webauthn\CeremonyStep;

use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\Counter\CounterChecker;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use function trigger_deprecation;

final readonly class CheckCounter implements CeremonyStep
{
    public function __construct(
        private CounterChecker $counterChecker
    ) {
    }

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
        $authData = $authenticatorResponse instanceof AuthenticatorAssertionResponse ? $authenticatorResponse->authenticatorData : $authenticatorResponse->attestationObject->authData;
        $storedCounter = $credentialRecord->counter;
        $responseCounter = $authData->signCount;
        if ($responseCounter !== 0 || $storedCounter !== 0) {
            $this->counterChecker->check($credentialRecord, $responseCounter);
        }
        $credentialRecord->counter = $responseCounter;
    }
}
