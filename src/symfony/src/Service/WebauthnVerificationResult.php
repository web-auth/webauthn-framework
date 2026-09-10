<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Outcome of a successful verification produced by
 * {@see WebauthnAttestationVerifier::verify()} or
 * {@see WebauthnAssertionVerifier::verify()}.
 *
 * Carries the validated credential record (the only piece a `SuccessHandler`
 * traditionally received), the deserialized {@see PublicKeyCredential} (useful
 * for the Signal API and for logging) and the user entity loaded from the
 * options storage when one was associated with the ceremony.
 */
final readonly class WebauthnVerificationResult
{
    public function __construct(
        public CredentialRecord $credentialRecord,
        public PublicKeyCredential $publicKeyCredential,
        public ?PublicKeyCredentialUserEntity $userEntity = null,
    ) {
    }
}
