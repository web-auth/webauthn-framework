<?php

declare(strict_types=1);

namespace Webauthn\CeremonyStep;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\CredentialRecord;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\MetadataService\CanLogData;
use Webauthn\MetadataService\CertificateChain\CertificateChainValidator;
use Webauthn\MetadataService\CertificateChain\CertificateToolbox;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\MetadataService\Statement\MetadataStatement;
use Webauthn\MetadataService\StatusReportRepository;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\CertificateTrustPath;
use function count;
use function in_array;
use function sprintf;
use function trigger_deprecation;

final class CheckMetadataStatement implements CeremonyStep, CanLogData
{
    private LoggerInterface $logger;

    private null|MetadataStatementRepository $metadataStatementRepository = null;

    private null|StatusReportRepository $statusReportRepository = null;

    private null|CertificateChainValidator $certificateChainValidator = null;

    public function __construct()
    {
        $this->logger = new NullLogger();
    }

    public function enableMetadataStatementSupport(
        MetadataStatementRepository $metadataStatementRepository,
        StatusReportRepository $statusReportRepository,
        CertificateChainValidator $certificateChainValidator
    ): void {
        $this->metadataStatementRepository = $metadataStatementRepository;
        $this->statusReportRepository = $statusReportRepository;
        $this->certificateChainValidator = $certificateChainValidator;
    }

    public function enableCertificateChainValidator(CertificateChainValidator $certificateChainValidator): void
    {
        $this->certificateChainValidator = $certificateChainValidator;
    }

    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
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

        /**
         * RP does not want to verify the authentication attestation.
         * @see https://www.w3.org/TR/webauthn-3/#dom-attestationconveyancepreference-none
         */
        if (in_array(
            $publicKeyCredentialOptions->attestation,
            [null, PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE],
            true
        )) {
            return;
        }

        /**
         * No trust path available for verification
         *
         * @see https://www.w3.org/TR/webauthn-3/#none
         * @see https://www.w3.org/TR/webauthn-3/#self
         */
        if (in_array(
            $attestationStatement->type,
            [AttestationStatement::TYPE_NONE, AttestationStatement::TYPE_SELF],
            true
        )) {
            return;
        }

        $aaguid = $attestedCredentialData->aaguid
            ->__toString();
        /**
         * All-zeros AAGUID: either privacy placeholder or U2F device (which predates AAGUID).
         * 1) Privacy Placeholder indicates the authenticator does not provide detailed information.
         * 2) U2F device can not provide useful AAGUID.
         *
         * So Metadata Statement lookup by AAGUID not possible, skip it.
         *
         * @see https://www.w3.org/TR/webauthn-3/#sctn-createCredential
         * @see https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#u2f-authenticatorMakeCredential-interoperability
         */
        if ($aaguid === '00000000-0000-0000-0000-000000000000') {
            return;
        }

        //The MDS Repository is mandatory here
        $this->metadataStatementRepository !== null || throw AuthenticatorResponseVerificationException::create(
            'The Metadata Statement Repository is mandatory when requesting attestation objects.'
        );
        $metadataStatement = $this->metadataStatementRepository->findOneByAAGUID($aaguid);
        // At this point, the Metadata Statement is mandatory
        $metadataStatement !== null || throw AuthenticatorResponseVerificationException::create(
            sprintf('The Metadata Statement for the AAGUID "%s" is missing', $aaguid)
        );
        // We check the last status report
        $this->checkStatusReport($aaguid);
        // We check the certificate chain (if any)
        $this->checkCertificateChain($attestationStatement, $metadataStatement);
        // Check Attestation Type is allowed
        if (count($metadataStatement->attestationTypes) !== 0) {
            $type = $this->getAttestationType($attestationStatement);
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

    private function checkStatusReport(string $aaguid): void
    {
        $statusReports = $this->statusReportRepository === null ? [] : $this->statusReportRepository->findStatusReportsByAAGUID(
            $aaguid
        );
        if (count($statusReports) !== 0) {
            $lastStatusReport = end($statusReports);
            if ($lastStatusReport->isCompromised()) {
                throw AuthenticatorResponseVerificationException::create(
                    'The authenticator is compromised and cannot be used'
                );
            }
        }
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
