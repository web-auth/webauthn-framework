<?php

declare(strict_types=1);

namespace Webauthn\Event;

use Webauthn\CredentialRecord;
use Webauthn\MetadataService\Statement\MetadataStatement;
use Webauthn\MetadataService\Statement\StatusReport;

/**
 * Dispatched when a full attestation (basic, AttCA or AnonCA) passes the Metadata Statement checks of a registration.
 *
 * The authenticator model is verified when the certificate chain was verified up to the roots of its Metadata
 * Statement. When the metadata have no statement for the AAGUID, the null AAGUID included, and the metadata support
 * does not require one, the Metadata Statement is null: the model is only declared by the authenticator.
 *
 * It is not dispatched for a self or none attestation, which carries no certificate chain, nor for an enterprise
 * attestation verified up to the trust anchors pinned for the enterprise attestations, which is never accepted
 * unverified.
 */
final readonly class AttestationCheckedAgainstMetadata implements WebauthnEvent
{
    /**
     * @param StatusReport[] $statusReports
     */
    public function __construct(
        public CredentialRecord $credentialRecord,
        public ?MetadataStatement $metadataStatement,
        public array $statusReports,
    ) {
    }

    public function isVerified(): bool
    {
        return $this->metadataStatement !== null;
    }
}
