<?php

declare(strict_types=1);

namespace Webauthn\Event;

use function array_filter;
use function array_values;
use Webauthn\CredentialRecord;
use Webauthn\MetadataService\Statement\MetadataStatement;
use Webauthn\MetadataService\Statement\StatusReport;

/**
 * Dispatched during a registration when at least one status report of the authenticator model says it is compromised
 * or revoked ({@see StatusReport::isCompromised()}).
 *
 * The registration is refused unless a listener calls admit(), for instance to keep registering a model under a
 * security notification for a time the application sets, while it replaces its fleet. The event carries every status
 * report of the AAGUID, in the order of the repository, so that the decision can take a later update into account.
 *
 * The Metadata Statement is null when the metadata have no statement for the AAGUID, or when the attestation is
 * verified up to the trust anchors pinned for the enterprise attestations.
 *
 * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-stat-rep
 */
final class CompromisedAuthenticatorDetected implements WebauthnEvent
{
    private bool $admitted = false;

    /**
     * @param StatusReport[] $statusReports
     */
    public function __construct(
        public readonly CredentialRecord $credentialRecord,
        public readonly ?MetadataStatement $metadataStatement,
        public readonly array $statusReports,
    ) {
    }

    /**
     * @return StatusReport[] The status reports that say the authenticator is compromised or revoked
     */
    public function compromisedStatusReports(): array
    {
        return array_values(
            array_filter(
                $this->statusReports,
                static fn (StatusReport $statusReport): bool => $statusReport->isCompromised()
            )
        );
    }

    public function admit(): void
    {
        $this->admitted = true;
    }

    public function isAdmitted(): bool
    {
        return $this->admitted;
    }
}
