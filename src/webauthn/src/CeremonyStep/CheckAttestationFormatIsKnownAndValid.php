<?php

declare(strict_types=1);

namespace Webauthn\CeremonyStep;

use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\CredentialRecord;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use function trigger_deprecation;

final readonly class CheckAttestationFormatIsKnownAndValid implements CeremonyStep
{
    public function __construct(
        private AttestationStatementSupportManager $attestationStatementSupportManager,
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
        $attestationObject = $authenticatorResponse->attestationObject;
        if ($attestationObject === null) {
            return;
        }

        $fmt = $attestationObject->attStmt
            ->fmt;
        $this->attestationStatementSupportManager->has(
            $fmt
        ) || throw AuthenticatorResponseVerificationException::create('Unsupported attestation statement format.');

        $attestationStatementSupport = $this->attestationStatementSupportManager->get($fmt);
        $clientDataJSONHash = hash('sha256', $authenticatorResponse->clientDataJSON ->rawData, true);
        $attestationStatementSupport->isValid(
            $clientDataJSONHash,
            $attestationObject->attStmt,
            $attestationObject->authData
        ) || throw AuthenticatorResponseVerificationException::create('Invalid attestation statement.');
    }
}
