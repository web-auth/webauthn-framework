<?php

declare(strict_types=1);

namespace Webauthn;

use Assert\Assertion;
use function count;
use function in_array;
use InvalidArgumentException;
use function is_string;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use function Safe\parse_url;
use Symfony\Component\Uid\Uuid;
use Throwable;
use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\CertificateChainChecker\CertificateChainChecker;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\MetadataService\Statement\MetadataStatement;
use Webauthn\MetadataService\StatusReportRepository;
use Webauthn\TokenBinding\TokenBindingHandler;
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\EmptyTrustPath;

class AuthenticatorAttestationResponseValidator
{
    private LoggerInterface $logger;

    private ?MetadataStatementRepository $metadataStatementRepository = null;

    private ?StatusReportRepository $statusReportRepository = null;

    private ?CertificateChainChecker $certificateChainChecker = null;

    public function __construct(
        private readonly AttestationStatementSupportManager $attestationStatementSupportManager,
        private readonly PublicKeyCredentialSourceRepository $publicKeyCredentialSource,
        private readonly TokenBindingHandler $tokenBindingHandler,
        private readonly ExtensionOutputCheckerHandler $extensionOutputCheckerHandler
    ) {
        $this->logger = new NullLogger();
    }

    public static function create(
        AttestationStatementSupportManager $attestationStatementSupportManager,
        PublicKeyCredentialSourceRepository $publicKeyCredentialSource,
        TokenBindingHandler $tokenBindingHandler,
        ExtensionOutputCheckerHandler $extensionOutputCheckerHandler
    ): self {
        return new self(
            $attestationStatementSupportManager,
            $publicKeyCredentialSource,
            $tokenBindingHandler,
            $extensionOutputCheckerHandler
        );
    }

    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;

        return $this;
    }

    public function setCertificateChainChecker(): self
    {
        return $this;
    }

    public function enableMetadataStatementSupport(
        MetadataStatementRepository $metadataStatementRepository,
        StatusReportRepository $statusReportRepository,
        CertificateChainChecker $certificateChainChecker,
    ): self {
        $this->metadataStatementRepository = $metadataStatementRepository;
        $this->certificateChainChecker = $certificateChainChecker;
        $this->statusReportRepository = $statusReportRepository;

        return $this;
    }

    /**
     * @param string[] $securedRelyingPartyId
     *
     * @see https://www.w3.org/TR/webauthn/#registering-a-new-credential
     */
    public function check(
        AuthenticatorAttestationResponse $authenticatorAttestationResponse,
        PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        ServerRequestInterface $request,
        array $securedRelyingPartyId = []
    ): PublicKeyCredentialSource {
        try {
            $this->logger->info('Checking the authenticator attestation response', [
                'authenticatorAttestationResponse' => $authenticatorAttestationResponse,
                'publicKeyCredentialCreationOptions' => $publicKeyCredentialCreationOptions,
                'host' => $request->getUri()
                    ->getHost(),
            ]);
            //Nothing to do

            $C = $authenticatorAttestationResponse->getClientDataJSON();

            Assertion::eq('webauthn.create', $C->getType(), 'The client data type is not "webauthn.create".');

            Assertion::true(
                hash_equals($publicKeyCredentialCreationOptions->getChallenge(), $C->getChallenge()),
                'Invalid challenge.'
            );

            $rpId = $publicKeyCredentialCreationOptions->getRp()
                ->getId() ?? $request->getUri()
                ->getHost()
                ;
            $facetId = $this->getFacetId(
                $rpId,
                $publicKeyCredentialCreationOptions->getExtensions(),
                $authenticatorAttestationResponse->getAttestationObject()
                    ->getAuthData()
                    ->getExtensions()
            );

            $parsedRelyingPartyId = parse_url($C->getOrigin());
            Assertion::isArray($parsedRelyingPartyId, sprintf('The origin URI "%s" is not valid', $C->getOrigin()));
            Assertion::keyExists($parsedRelyingPartyId, 'scheme', 'Invalid origin rpId.');
            $clientDataRpId = $parsedRelyingPartyId['host'] ?? '';
            Assertion::notEmpty($clientDataRpId, 'Invalid origin rpId.');
            $rpIdLength = mb_strlen($facetId);
            Assertion::eq(mb_substr('.' . $clientDataRpId, -($rpIdLength + 1)), '.' . $facetId, 'rpId mismatch.');

            if (! in_array($facetId, $securedRelyingPartyId, true)) {
                $scheme = $parsedRelyingPartyId['scheme'];
                Assertion::eq('https', $scheme, 'Invalid scheme. HTTPS required.');
            }

            if ($C->getTokenBinding() !== null) {
                $this->tokenBindingHandler->check($C->getTokenBinding(), $request);
            }

            $clientDataJSONHash = hash(
                'sha256',
                $authenticatorAttestationResponse->getClientDataJSON()
                    ->getRawData(),
                true
            );

            $attestationObject = $authenticatorAttestationResponse->getAttestationObject();

            $rpIdHash = hash('sha256', $facetId, true);
            Assertion::true(
                hash_equals($rpIdHash, $attestationObject->getAuthData()->getRpIdHash()),
                'rpId hash mismatch.'
            );

            if ($publicKeyCredentialCreationOptions->getAuthenticatorSelection()->getUserVerification() === AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED) {
                Assertion::true($attestationObject->getAuthData()->isUserPresent(), 'User was not present');
                Assertion::true($attestationObject->getAuthData()->isUserVerified(), 'User authentication required.');
            }

            $extensionsClientOutputs = $attestationObject->getAuthData()
                ->getExtensions()
            ;
            if ($extensionsClientOutputs !== null) {
                $this->extensionOutputCheckerHandler->check(
                    $publicKeyCredentialCreationOptions->getExtensions(),
                    $extensionsClientOutputs
                );
            }

            $this->checkMetadataStatement($publicKeyCredentialCreationOptions, $attestationObject);
            $fmt = $attestationObject->getAttStmt()
                ->getFmt()
            ;
            Assertion::true(
                $this->attestationStatementSupportManager->has($fmt),
                'Unsupported attestation statement format.'
            );

            $attestationStatementSupport = $this->attestationStatementSupportManager->get($fmt);
            Assertion::true(
                $attestationStatementSupport->isValid(
                    $clientDataJSONHash,
                    $attestationObject->getAttStmt(),
                    $attestationObject->getAuthData()
                ),
                'Invalid attestation statement.'
            );

            Assertion::true(
                $attestationObject->getAuthData()
                    ->hasAttestedCredentialData(),
                'There is no attested credential data.'
            );
            $attestedCredentialData = $attestationObject->getAuthData()
                ->getAttestedCredentialData()
            ;
            Assertion::notNull($attestedCredentialData, 'There is no attested credential data.');
            $credentialId = $attestedCredentialData->getCredentialId();
            Assertion::null(
                $this->publicKeyCredentialSource->findOneByCredentialId($credentialId),
                'The credential ID already exists.'
            );

            $publicKeyCredentialSource = $this->createPublicKeyCredentialSource(
                $credentialId,
                $attestedCredentialData,
                $attestationObject,
                $publicKeyCredentialCreationOptions->getUser()
                    ->getId()
            );
            $this->logger->info('The attestation is valid');
            $this->logger->debug('Public Key Credential Source', [
                'publicKeyCredentialSource' => $publicKeyCredentialSource,
            ]);

            return $publicKeyCredentialSource;
        } catch (Throwable $throwable) {
            $this->logger->error('An error occurred', [
                'exception' => $throwable,
            ]);
            throw $throwable;
        }
    }

    private function checkCertificateChain(
        AttestationStatement $attestationStatement,
        ?MetadataStatement $metadataStatement
    ): void {
        $trustPath = $attestationStatement->getTrustPath();
        if (! $trustPath instanceof CertificateTrustPath) {
            return;
        }
        $authenticatorCertificates = $trustPath->getCertificates();

        if ($metadataStatement === null) {
            $this->certificateChainChecker?->check($authenticatorCertificates, []);

            return;
        }

        $trustedCertificates = array_merge(
            $metadataStatement->getAttestationRootCertificates(),
            $metadataStatement->getRootCertificates()
        );
        $trustedCertificates = CertificateToolbox::fixPEMStructures($trustedCertificates);

        $this->certificateChainChecker?->check($authenticatorCertificates, $trustedCertificates);
    }

    private function checkMetadataStatement(
        PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        AttestationObject $attestationObject
    ): void {
        $attestationStatement = $attestationObject->getAttStmt();
        $attestedCredentialData = $attestationObject->getAuthData()
            ->getAttestedCredentialData()
        ;
        Assertion::notNull($attestedCredentialData, 'No attested credential data found');
        $aaguid = $attestedCredentialData->getAaguid()
            ->__toString()
        ;
        if ($publicKeyCredentialCreationOptions->getAttestation() === PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE) {
            $this->logger->debug('No attestation is asked.');
            //No attestation is asked. We shall ensure that the data is anonymous.
            if (
                $aaguid === '00000000-0000-0000-0000-000000000000'
                && ($attestationStatement->getType() === AttestationStatement::TYPE_NONE || $attestationStatement->getType() === AttestationStatement::TYPE_SELF)) {
                $this->logger->debug('The Attestation Statement is anonymous.');
                $this->checkCertificateChain($attestationStatement, null);

                return;
            }
            $this->logger->debug('Anonymization required. AAGUID and Attestation Statement changed.', [
                'aaguid' => $aaguid,
                'AttestationStatement' => $attestationStatement,
            ]);
            $attestedCredentialData->setAaguid(Uuid::fromString('00000000-0000-0000-0000-000000000000'));
            $attestationObject->setAttStmt(AttestationStatement::createNone('none', [], new EmptyTrustPath()));

            return;
        }

        // If no Attestation Statement has been returned or if null AAGUID (=00000000-0000-0000-0000-000000000000)
        // => nothing to check
        if ($attestationStatement->getType() === AttestationStatement::TYPE_NONE) {
            $this->logger->debug('No attestation returned.');
            //No attestation is returned. We shall ensure that the AAGUID is a null one.
            if ($aaguid !== '00000000-0000-0000-0000-000000000000') {
                $this->logger->debug('Anonymization required. AAGUID and Attestation Statement changed.', [
                    'aaguid' => $aaguid,
                    'AttestationStatement' => $attestationStatement,
                ]);
                $attestedCredentialData->setAaguid(Uuid::fromString('00000000-0000-0000-0000-000000000000'));

                return;
            }

            return;
        }

        if ($aaguid === '00000000-0000-0000-0000-000000000000') {
            //No need to continue if the AAGUID is null.
            // This could be the case e.g. with AnonCA type
            return;
        }

        //The MDS Repository is mandatory here
        Assertion::notNull(
            $this->metadataStatementRepository,
            'The Metadata Statement Repository is mandatory when requesting attestation objects.'
        );
        $metadataStatement = $this->metadataStatementRepository->findOneByAAGUID($aaguid);

        // We check the last status report
        $this->checkStatusReport($aaguid);

        // We check the certificate chain (if any)
        $this->checkCertificateChain($attestationStatement, $metadataStatement);

        // At this point, the Metadata Statement is mandatory
        Assertion::notNull(
            $metadataStatement,
            sprintf('The Metadata Statement for the AAGUID "%s" is missing', $aaguid)
        );

        // Check Attestation Type is allowed
        if (count($metadataStatement->getAttestationTypes()) !== 0) {
            $type = $this->getAttestationType($attestationStatement);
            Assertion::inArray(
                $type,
                $metadataStatement->getAttestationTypes(),
                sprintf(
                    'Invalid attestation statement. The attestation type "%s" is not allowed for this authenticator.',
                    $type
                )
            );
        }
    }

    private function getAttestationType(AttestationStatement $attestationStatement): string
    {
        return match ($attestationStatement->getType()) {
            AttestationStatement::TYPE_BASIC => MetadataStatement::ATTESTATION_BASIC_FULL,
            AttestationStatement::TYPE_SELF => MetadataStatement::ATTESTATION_BASIC_SURROGATE,
            AttestationStatement::TYPE_ATTCA => MetadataStatement::ATTESTATION_ATTCA,
            AttestationStatement::TYPE_ECDAA => MetadataStatement::ATTESTATION_ECDAA,
            default => throw new InvalidArgumentException('Invalid attestation type'),
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
                throw new LogicException('The authenticator is compromised and cannot be used');
            }
        }
    }

    private function createPublicKeyCredentialSource(
        string $credentialId,
        AttestedCredentialData $attestedCredentialData,
        AttestationObject $attestationObject,
        string $userHandle
    ): PublicKeyCredentialSource {
        $credentialPublicKey = $attestedCredentialData->getCredentialPublicKey();
        Assertion::notNull($credentialPublicKey, 'Not credential public key available in the attested credential data');

        return new PublicKeyCredentialSource(
            $credentialId,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            $attestationObject->getAttStmt()
                ->getType(),
            $attestationObject->getAttStmt()
                ->getTrustPath(),
            $attestedCredentialData->getAaguid(),
            $credentialPublicKey,
            $userHandle,
            $attestationObject->getAuthData()
                ->getSignCount()
        );
    }

    private function getFacetId(
        string $rpId,
        AuthenticationExtensionsClientInputs $authenticationExtensionsClientInputs,
        ?AuthenticationExtensionsClientOutputs $authenticationExtensionsClientOutputs
    ): string {
        if ($authenticationExtensionsClientOutputs === null || ! $authenticationExtensionsClientInputs->has(
            'appid'
        ) || ! $authenticationExtensionsClientOutputs->has('appid')) {
            return $rpId;
        }
        $appId = $authenticationExtensionsClientInputs->get('appid')
            ->value()
        ;
        $wasUsed = $authenticationExtensionsClientOutputs->get('appid')
            ->value()
        ;
        if (! is_string($appId) || $wasUsed !== true) {
            return $rpId;
        }

        return $appId;
    }
}
