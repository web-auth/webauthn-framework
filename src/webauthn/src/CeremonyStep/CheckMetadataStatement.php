<?php

declare(strict_types=1);

namespace Webauthn\CeremonyStep;

use function count;
use function in_array;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use function sprintf;
use function trigger_deprecation;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\CredentialRecord;
use Webauthn\Event\AttestationCheckedAgainstMetadata;
use Webauthn\Event\CanDispatchEvents;
use Webauthn\Event\CompromisedAuthenticatorDetected;
use Webauthn\Event\NullEventDispatcher;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\MetadataService\CanLogData;
use Webauthn\MetadataService\CertificateChain\CertificateChainValidator;
use Webauthn\MetadataService\CertificateChain\CertificateToolbox;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\MetadataService\Statement\MetadataStatement;
use Webauthn\MetadataService\Statement\StatusReport;
use Webauthn\MetadataService\StatusReportRepository;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\CertificateTrustPath;

final class CheckMetadataStatement implements CeremonyStep, CanLogData, CanDispatchEvents
{
    private LoggerInterface $logger;

    private EventDispatcherInterface $eventDispatcher;

    private null|MetadataStatementRepository $metadataStatementRepository = null;

    private null|StatusReportRepository $statusReportRepository = null;

    private null|CertificateChainValidator $certificateChainValidator = null;

    private bool $requireStatement = true;

    /**
     * @var string[]
     */
    private array $enterpriseAttestationTrustAnchors = [];

    public function __construct()
    {
        $this->logger = new NullLogger();
        $this->eventDispatcher = new NullEventDispatcher();
    }

    /**
     * When $requireStatement is false, a full attestation (basic, AttCA or AnonCA) whose AAGUID has no Metadata
     * Statement, the null AAGUID included, passes without its certificate chain being verified instead of being
     * refused. WebAuthn Level 3 lets a Relying Party register such a credential and treat it as one with self
     * attestation. The status reports of the AAGUID still apply, and {@see AttestationCheckedAgainstMetadata} tells
     * the application whether the authenticator model was verified or only declared.
     *
     * @see https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
     */
    public function enableMetadataStatementSupport(
        MetadataStatementRepository $metadataStatementRepository,
        StatusReportRepository $statusReportRepository,
        CertificateChainValidator $certificateChainValidator,
        bool $requireStatement = true,
    ): void {
        $this->metadataStatementRepository = $metadataStatementRepository;
        $this->statusReportRepository = $statusReportRepository;
        $this->certificateChainValidator = $certificateChainValidator;
        $this->requireStatement = $requireStatement;
    }

    public function enableCertificateChainValidator(CertificateChainValidator $certificateChainValidator): void
    {
        $this->certificateChainValidator = $certificateChainValidator;
    }

    /**
     * Under the "enterprise" attestation conveyance preference, a full attestation is verified up to these trust
     * anchors only, PEM or Base64-encoded DER certificates, whether its AAGUID has a metadata statement or not. The
     * status reports of the AAGUID still apply.
     *
     * @param string[] $trustAnchors
     *
     * @see https://www.w3.org/TR/webauthn-3/#dom-attestationconveyancepreference-enterprise
     */
    public function setEnterpriseAttestationTrustAnchors(array $trustAnchors): void
    {
        $this->enterpriseAttestationTrustAnchors = $trustAnchors;
    }

    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    public function setEventDispatcher(EventDispatcherInterface $eventDispatcher): void
    {
        $this->eventDispatcher = $eventDispatcher;
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
        if (
            ! $publicKeyCredentialOptions instanceof PublicKeyCredentialCreationOptions
            || ! $authenticatorResponse instanceof AuthenticatorAttestationResponse
        ) {
            return;
        }

        $attestationStatement = $authenticatorResponse->attestationObject->attStmt;
        $attestedCredentialData = $authenticatorResponse->attestationObject->authData
            ->attestedCredentialData;
        $attestedCredentialData !== null || throw AuthenticatorResponseVerificationException::create(
            'No attested credential data found'
        );

        if (! $this->isAttestationVerificationRequested($publicKeyCredentialOptions)) {
            $this->logger->debug('No attestation verification requested by RP.');
            return;
        }

        if ($attestationStatement->type === AttestationStatement::TYPE_NONE) {
            $this->logger->debug('None attestation format. No metadata verification required.');
            return;
        }

        $aaguid = $attestedCredentialData->aaguid
            ->__toString();
        if ($this->isPinnedEnterpriseAttestation($publicKeyCredentialOptions, $attestationStatement)) {
            $this->processPinnedEnterpriseAttestation($credentialRecord, $attestationStatement, $aaguid);
            return;
        }

        if ($this->isNullAaguid($aaguid) && $attestationStatement->type === AttestationStatement::TYPE_SELF) {
            $this->logger->debug('Null AAGUID detected with self attestation. Skipping metadata verification.', [
                'reason' => 'Privacy placeholder',
            ]);
            return;
        }

        if ($attestationStatement->type === AttestationStatement::TYPE_SELF) {
            $this->logger->debug('Self attestation detected.', [
                'aaguid' => $aaguid,
            ]);
            $this->processSelfAttestation($credentialRecord, $aaguid);
            return;
        }

        $this->logger->debug('Processing attestation with full metadata validation.', [
            'type' => $attestationStatement->type,
            'aaguid' => $aaguid,
        ]);
        $this->processWithMetadata($credentialRecord, $attestationStatement, $aaguid);
    }

    /**
     * Check if RP requested attestation verification.
     * @see https://www.w3.org/TR/webauthn-3/#dom-attestationconveyancepreference-none
     */
    private function isAttestationVerificationRequested(
        PublicKeyCredentialCreationOptions $publicKeyCredentialOptions
    ): bool {
        return ! in_array(
            $publicKeyCredentialOptions->attestation,
            [null, PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE],
            true
        );
    }

    private function isPinnedEnterpriseAttestation(
        PublicKeyCredentialCreationOptions $publicKeyCredentialOptions,
        AttestationStatement $attestationStatement
    ): bool {
        return $this->enterpriseAttestationTrustAnchors !== []
            && $publicKeyCredentialOptions->attestation === PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_ENTERPRISE
            && in_array($attestationStatement->type, [
                AttestationStatement::TYPE_BASIC,
                AttestationStatement::TYPE_ATTCA,
                AttestationStatement::TYPE_ANONCA,
            ], true);
    }

    private function processPinnedEnterpriseAttestation(
        CredentialRecord $credentialRecord,
        AttestationStatement $attestationStatement,
        string $aaguid
    ): void {
        $certificateChainValidator = $this->certificateChainValidator ?? throw AuthenticatorResponseVerificationException::create(
            'The Certificate Chain Validator is mandatory when trust anchors are pinned for enterprise attestations.'
        );
        $this->logger->debug('Enterprise attestation. Verifying it up to the pinned trust anchors.');

        $this->checkStatusReport($credentialRecord, $aaguid, null);
        $trustPath = $attestationStatement->trustPath;
        if (! $trustPath instanceof CertificateTrustPath) {
            throw AuthenticatorResponseVerificationException::create(
                'Certificate trust path is required for attestation verification'
            );
        }
        $certificateChainValidator->check(
            $trustPath->certificates,
            CertificateToolbox::fixPEMStructures($this->enterpriseAttestationTrustAnchors)
        );
    }

    /**
     * Check if AAGUID is all-zeros (privacy placeholder or U2F device).
     *
     * All-zeros AAGUID: either privacy placeholder or U2F device (which predates AAGUID).
     * 1) Privacy Placeholder indicates the authenticator does not provide detailed information.
     * 2) U2F device cannot provide useful AAGUID.
     *
     * So Metadata Statement lookup by AAGUID not possible.
     *
     * The verification is only skipped for self attestation, which has no trust path to verify. The AAGUID is written
     * by the authenticator: a full attestation (Basic, AttCA, AnonCA) under the null AAGUID still has to chain to the
     * trust anchors of a Metadata Statement, the one the repository returns for the null AAGUID (e.g. with the Apple
     * WebAuthn Root CA or the U2F vendor roots), or it is refused. When the metadata support does not require a
     * statement, it passes unverified instead, like the full attestation of any other AAGUID the metadata do not know.
     *
     * @see https://www.w3.org/TR/webauthn-3/#sctn-createCredential
     * @see https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#u2f-authenticatorMakeCredential-interoperability
     */
    private function isNullAaguid(string $aaguid): bool
    {
        return $aaguid === '00000000-0000-0000-0000-000000000000';
    }

    /**
     * Process self attestation: check MDS for compromised devices.
     *
     * Self attestation: authenticator uses credential key pair to sign attestation.
     * No attestation certificate chain to validate, but we still check MDS for compromised devices.
     *
     * @see https://www.w3.org/TR/webauthn-3/#self
     */
    private function processSelfAttestation(CredentialRecord $credentialRecord, string $aaguid): void
    {
        $metadataStatement = $this->metadataStatementRepository?->findOneByAAGUID($aaguid);
        if ($metadataStatement === null) {
            $this->logger->info('No metadata statement found for self attestation. Skipping MDS verification.', [
                'aaguid' => $aaguid,
            ]);
            return;
        }

        $this->logger->debug('Metadata statement found for self attestation. Checking status reports.', [
            'aaguid' => $aaguid,
        ]);
        $this->checkStatusReport($credentialRecord, $aaguid, $metadataStatement);
        // Note: We do NOT check attestationTypes for self attestation as the authenticator
        // is using its credential key (not attestation certificate), which may differ from
        // the declared attestation types in metadata (which describe certificate-based attestation).
    }

    /**
     * Process attestation with full metadata validation (Basic, AttCA, AnonCA).
     */
    private function processWithMetadata(
        CredentialRecord $credentialRecord,
        AttestationStatement $attestationStatement,
        string $aaguid
    ): void {
        $this->metadataStatementRepository !== null || throw AuthenticatorResponseVerificationException::create(
            'The Metadata Statement Repository is mandatory when requesting attestation objects.'
        );
        $metadataStatement = $this->metadataStatementRepository->findOneByAAGUID($aaguid);
        if ($metadataStatement === null) {
            $this->processWithoutMetadataStatement($credentialRecord, $aaguid);
            return;
        }

        $this->logger->debug('Metadata statement found. Starting validation.', [
            'aaguid' => $aaguid,
            'attestation_type' => $attestationStatement->type,
        ]);

        $statusReports = $this->checkStatusReport($credentialRecord, $aaguid, $metadataStatement);
        $this->logger->debug('Status report verification completed.');

        $this->checkCertificateChain($attestationStatement, $metadataStatement);
        $this->logger->debug('Certificate chain verification completed.');

        $this->checkAttestationTypeIsAllowed($attestationStatement, $metadataStatement);
        $this->logger->debug('Attestation type verification completed.');

        $this->eventDispatcher->dispatch(
            new AttestationCheckedAgainstMetadata($credentialRecord, $metadataStatement, $statusReports)
        );
    }

    /**
     * The status reports of the AAGUID still apply: a compromised authenticator is refused unless a listener admits it.
     *
     * @see self::enableMetadataStatementSupport()
     */
    private function processWithoutMetadataStatement(CredentialRecord $credentialRecord, string $aaguid): void
    {
        if ($this->requireStatement) {
            throw AuthenticatorResponseVerificationException::create(
                sprintf('The Metadata Statement for the AAGUID "%s" is missing', $aaguid)
            );
        }

        $statusReports = $this->checkStatusReport($credentialRecord, $aaguid, null);
        $this->logger->info('No metadata statement found. The attestation is accepted unverified.', [
            'aaguid' => $aaguid,
        ]);
        $this->eventDispatcher->dispatch(new AttestationCheckedAgainstMetadata($credentialRecord, null, $statusReports));
    }

    /**
     * Check if the attestation type is allowed for this authenticator.
     */
    private function checkAttestationTypeIsAllowed(
        AttestationStatement $attestationStatement,
        MetadataStatement $metadataStatement
    ): void {
        if (count($metadataStatement->attestationTypes) === 0) {
            $this->logger->debug('No attestation types restrictions in metadata statement.');
            return;
        }

        $type = $this->getAttestationType($attestationStatement);
        $this->logger->debug('Checking attestation type.', [
            'type' => $type,
            'allowed_types' => $metadataStatement->attestationTypes,
        ]);

        in_array(
            $type,
            $metadataStatement->attestationTypes,
            true
        ) || throw AuthenticatorResponseVerificationException::create(
            sprintf(
                'Invalid attestation statement. The attestation type "%s" is not allowed for this authenticator.',
                $type
            )
        );
    }

    private function getAttestationType(AttestationStatement $attestationStatement): string
    {
        return match ($attestationStatement->type) {
            AttestationStatement::TYPE_BASIC => MetadataStatement::ATTESTATION_BASIC_FULL,
            AttestationStatement::TYPE_SELF => MetadataStatement::ATTESTATION_BASIC_SURROGATE,
            AttestationStatement::TYPE_ATTCA => MetadataStatement::ATTESTATION_ATTCA,
            AttestationStatement::TYPE_ANONCA => MetadataStatement::ATTESTATION_ANONCA,
            default => throw AuthenticatorResponseVerificationException::create('Invalid attestation type'),
        };
    }

    /**
     * Refuses the authenticator model as soon as one of its status reports is a compromise or a revocation, unless a
     * listener of {@see CompromisedAuthenticatorDetected} admits it.
     *
     * Every report is read, wherever it sits in the list. The FIDO Metadata Service BLOB does not keep the reports
     * of an entry in chronological order (most entries list the newest first), so the last element of the array is
     * not the current status. A later report, such as an update or a new certification, does not clear a compromise
     * or a revocation either: the attestation does not tell whether the registering authenticator received the fix.
     *
     * @return StatusReport[]
     *
     * @see https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-stat-rep
     */
    private function checkStatusReport(
        CredentialRecord $credentialRecord,
        string $aaguid,
        ?MetadataStatement $metadataStatement
    ): array {
        $statusReports = $this->statusReportRepository?->findStatusReportsByAAGUID($aaguid) ?? [];
        if (count($statusReports) === 0) {
            $this->logger->debug('No status reports found for authenticator.', [
                'aaguid' => $aaguid,
            ]);
            return [];
        }

        $compromised = false;
        foreach ($statusReports as $statusReport) {
            $this->logger->debug('Status report found.', [
                'aaguid' => $aaguid,
                'status' => $statusReport->status,
            ]);

            if ($statusReport->isCompromised()) {
                $this->logger->warning('Authenticator is marked as compromised or revoked in MDS.', [
                    'aaguid' => $aaguid,
                    'status' => $statusReport->status,
                ]);
                $compromised = true;
            }
        }
        if (! $compromised) {
            return $statusReports;
        }

        $event = new CompromisedAuthenticatorDetected($credentialRecord, $metadataStatement, $statusReports);
        $this->eventDispatcher->dispatch($event);
        if (! $event->isAdmitted()) {
            throw AuthenticatorResponseVerificationException::create(
                'The authenticator is compromised and cannot be used'
            );
        }
        $this->logger->warning('The compromised authenticator is admitted by the application.', [
            'aaguid' => $aaguid,
        ]);

        return $statusReports;
    }

    private function checkCertificateChain(
        AttestationStatement $attestationStatement,
        MetadataStatement $metadataStatement
    ): void {
        $trustPath = $attestationStatement->trustPath;
        $trustPath instanceof CertificateTrustPath || throw AuthenticatorResponseVerificationException::create(
            'Certificate trust path is required for attestation verification'
        );
        $authenticatorCertificates = $trustPath->certificates;
        $trustedCertificates = CertificateToolbox::fixPEMStructures(
            $metadataStatement->attestationRootCertificates
        );
        $this->certificateChainValidator?->check($authenticatorCertificates, $trustedCertificates);
    }
}
