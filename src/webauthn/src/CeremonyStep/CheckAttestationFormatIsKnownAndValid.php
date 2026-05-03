<?php

declare(strict_types=1);

namespace Webauthn\CeremonyStep;

use function in_array;
use function sprintf;
use function trigger_deprecation;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\CredentialRecord;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;

final readonly class CheckAttestationFormatIsKnownAndValid implements CeremonyStep
{
    public function __construct(
        private AttestationStatementSupportManager $attestationStatementSupportManager,
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
        $attestationObject = $authenticatorResponse->attestationObject;
        if ($attestationObject === null) {
            return;
        }

        $fmt = $attestationObject->attStmt
            ->fmt;
        $this->attestationStatementSupportManager->has(
            $fmt
        ) || throw AuthenticatorResponseVerificationException::create('Unsupported attestation statement format.');

        // WebAuthn L3 §5.4 / §5.5: when the relying party advertised a list of
        // preferred attestation formats, the format actually emitted by the
        // authenticator MUST be one of them. An empty list keeps the historical
        // behaviour (any supported format is accepted).
        $requestedFormats = $publicKeyCredentialOptions->attestationFormats;
        if ($requestedFormats !== [] && ! in_array($fmt, $requestedFormats, true)) {
            throw AuthenticatorResponseVerificationException::create(sprintf(
                'The attestation statement format "%s" is not in the list requested by the relying party.',
                $fmt,
            ));
        }

        $attestationStatementSupport = $this->attestationStatementSupportManager->get($fmt);
        $clientDataJSONHash = hash('sha256', $authenticatorResponse->clientDataJSON ->rawData, true);
        $attestationStatementSupport->isValid(
            $clientDataJSONHash,
            $attestationObject->attStmt,
            $attestationObject->authData
        ) || throw AuthenticatorResponseVerificationException::create('Invalid attestation statement.');
    }
}
