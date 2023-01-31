<?php

declare(strict_types=1);

namespace Webauthn;

use function array_key_exists;
use function count;
use function in_array;
use function is_array;
use function is_string;
use function parse_url;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Uid\Uuid;
use Throwable;
use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\Event\AuthenticatorAttestationResponseValidationFailedEvent;
use Webauthn\Event\AuthenticatorAttestationResponseValidationSucceededEvent;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\MetadataService\CanLogData;
use Webauthn\MetadataService\CertificateChain\CertificateChainValidator;
use Webauthn\MetadataService\CertificateChain\CertificateToolbox;
use Webauthn\MetadataService\Event\CanDispatchEvents;
use Webauthn\MetadataService\Event\NullEventDispatcher;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\MetadataService\Statement\MetadataStatement;
use Webauthn\MetadataService\StatusReportRepository;
use Webauthn\TokenBinding\TokenBindingHandler;
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\EmptyTrustPath;

class AuthenticatorAttestationResponseValidator implements CanLogData, CanDispatchEvents
{
    private LoggerInterface $logger;

    private EventDispatcherInterface $eventDispatcher;

    private ?MetadataStatementRepository $metadataStatementRepository = null;

    private ?StatusReportRepository $statusReportRepository = null;

    private ?CertificateChainValidator $certificateChainValidator = null;

    public function __construct(
        private readonly AttestationStatementSupportManager $attestationStatementSupportManager,
        private readonly PublicKeyCredentialSourceRepository $publicKeyCredentialSource,
        private readonly ?TokenBindingHandler $tokenBindingHandler,
        private readonly ExtensionOutputCheckerHandler $extensionOutputCheckerHandler,
        ?EventDispatcherInterface $eventDispatcher = null,
    ) {
        if ($this->tokenBindingHandler !== null) {
            trigger_deprecation(
                'web-auth/webauthn-symfony-bundle',
                '4.3.0',
                'The parameter "$tokenBindingHandler" is deprecated since 4.3.0 and will be removed in 5.0.0. Please set "null" instead.'
            );
        }
        if ($eventDispatcher === null) {
            $this->eventDispatcher = new NullEventDispatcher();
        } else {
            $this->eventDispatcher = $eventDispatcher;
            trigger_deprecation(
                'web-auth/webauthn-symfony-bundle',
                '4.5.0',
                'The parameter "$eventDispatcher" is deprecated since 4.5.0 will be removed in 5.0.0. Please use `setEventDispatcher` instead.'
            );
        }
        $this->logger = new NullLogger();
    }

    public static function create(
        AttestationStatementSupportManager $attestationStatementSupportManager,
        PublicKeyCredentialSourceRepository $publicKeyCredentialSource,
        ?TokenBindingHandler $tokenBindingHandler,
        ExtensionOutputCheckerHandler $extensionOutputCheckerHandler,
        ?EventDispatcherInterface $eventDispatcher = null
    ): self {
        return new self(
            $attestationStatementSupportManager,
            $publicKeyCredentialSource,
            $tokenBindingHandler,
            $extensionOutputCheckerHandler,
            $eventDispatcher,
        );
    }

    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    public function setEventDispatcher(EventDispatcherInterface $eventDispatcher): void
    {
        $this->eventDispatcher = $eventDispatcher;
    }

    public function setCertificateChainValidator(): self
    {
        return $this;
    }

    public function enableMetadataStatementSupport(
        MetadataStatementRepository $metadataStatementRepository,
        StatusReportRepository $statusReportRepository,
        CertificateChainValidator $certificateChainValidator
    ): self {
        $this->metadataStatementRepository = $metadataStatementRepository;
        $this->certificateChainValidator = $certificateChainValidator;
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
        ServerRequestInterface|string $request,
        array $securedRelyingPartyId = []
    ): PublicKeyCredentialSource {
        if ($request instanceof ServerRequestInterface) {
            trigger_deprecation(
                'web-auth/webauthn-lib',
                '4.5.0',
                sprintf(
                    'Passing a %s to the method `check` of the class "%s" is deprecated since 4.5.0 and will be removed in 5.0.0. Please inject the host as a string instead.',
                    ServerRequestInterface::class,
                    self::class
                )
            );
        }
        try {
            $this->logger->info('Checking the authenticator attestation response', [
                'authenticatorAttestationResponse' => $authenticatorAttestationResponse,
                'publicKeyCredentialCreationOptions' => $publicKeyCredentialCreationOptions,
                'host' => is_string($request) ? $request : $request->getUri()
                    ->getHost(),
            ]);
            //Nothing to do
            $C = $authenticatorAttestationResponse->getClientDataJSON();
            $C->getType() === 'webauthn.create' || throw AuthenticatorResponseVerificationException::create(
                'The client data type is not "webauthn.create".'
            );
            hash_equals(
                $publicKeyCredentialCreationOptions->getChallenge(),
                $C->getChallenge()
            ) || throw AuthenticatorResponseVerificationException::create('Invalid challenge.');
            $rpId = $publicKeyCredentialCreationOptions->getRp()
                ->getId() ?? (is_string($request) ? $request : $request->getUri()->getHost());
            $facetId = $this->getFacetId(
                $rpId,
                $publicKeyCredentialCreationOptions->getExtensions(),
                $authenticatorAttestationResponse->getAttestationObject()
                    ->getAuthData()
                    ->getExtensions()
            );
            $parsedRelyingPartyId = parse_url($C->getOrigin());
            is_array($parsedRelyingPartyId) || throw AuthenticatorResponseVerificationException::create(
                sprintf('The origin URI "%s" is not valid', $C->getOrigin())
            );
            array_key_exists(
                'scheme',
                $parsedRelyingPartyId
            ) || throw AuthenticatorResponseVerificationException::create('Invalid origin rpId.');
            $clientDataRpId = $parsedRelyingPartyId['host'] ?? '';
            $clientDataRpId !== '' || throw AuthenticatorResponseVerificationException::create('Invalid origin rpId.');
            $rpIdLength = mb_strlen($facetId);
            mb_substr(
                '.' . $clientDataRpId,
                -($rpIdLength + 1)
            ) === '.' . $facetId || throw AuthenticatorResponseVerificationException::create('rpId mismatch.');
            if (! in_array($facetId, $securedRelyingPartyId, true)) {
                $scheme = $parsedRelyingPartyId['scheme'];
                $scheme === 'https' || throw AuthenticatorResponseVerificationException::create(
                    'Invalid scheme. HTTPS required.'
                );
            }
            if (! is_string($request) && $C->getTokenBinding() !== null) {
                $this->tokenBindingHandler?->check($C->getTokenBinding(), $request);
            }
            $clientDataJSONHash = hash(
                'sha256',
                $authenticatorAttestationResponse->getClientDataJSON()
                    ->getRawData(),
                true
            );
            $attestationObject = $authenticatorAttestationResponse->getAttestationObject();
            $rpIdHash = hash('sha256', $facetId, true);
            hash_equals(
                $rpIdHash,
                $attestationObject->getAuthData()
                    ->getRpIdHash()
            ) || throw AuthenticatorResponseVerificationException::create('rpId hash mismatch.');
            if ($publicKeyCredentialCreationOptions->getAuthenticatorSelection()?->getUserVerification() === AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED) {
                $attestationObject->getAuthData()
                    ->isUserPresent() || throw AuthenticatorResponseVerificationException::create(
                        'User was not present'
                    );
                $attestationObject->getAuthData()
                    ->isUserVerified() || throw AuthenticatorResponseVerificationException::create(
                        'User authentication required.'
                    );
            }
            $extensionsClientOutputs = $attestationObject->getAuthData()
                ->getExtensions();
            if ($extensionsClientOutputs !== null) {
                $this->extensionOutputCheckerHandler->check(
                    $publicKeyCredentialCreationOptions->getExtensions(),
                    $extensionsClientOutputs
                );
            }
            $this->checkMetadataStatement($publicKeyCredentialCreationOptions, $attestationObject);
            $fmt = $attestationObject->getAttStmt()
                ->getFmt();
            $this->attestationStatementSupportManager->has(
                $fmt
            ) || throw AuthenticatorResponseVerificationException::create(
                'Unsupported attestation statement format.'
            );
            $attestationStatementSupport = $this->attestationStatementSupportManager->get($fmt);
            $attestationStatementSupport->isValid(
                $clientDataJSONHash,
                $attestationObject->getAttStmt(),
                $attestationObject->getAuthData()
            ) || throw AuthenticatorResponseVerificationException::create('Invalid attestation statement.');
            $attestationObject->getAuthData()
                ->hasAttestedCredentialData() || throw AuthenticatorResponseVerificationException::create(
                    'There is no attested credential data.'
                );
            $attestedCredentialData = $attestationObject->getAuthData()
                ->getAttestedCredentialData();
            $attestedCredentialData !== null || throw AuthenticatorResponseVerificationException::create(
                'There is no attested credential data.'
            );
            $credentialId = $attestedCredentialData->getCredentialId();
            $this->publicKeyCredentialSource->findOneByCredentialId(
                $credentialId
            ) === null || throw AuthenticatorResponseVerificationException::create(
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
            $this->eventDispatcher->dispatch(
                $this->createAuthenticatorAttestationResponseValidationSucceededEvent(
                    $authenticatorAttestationResponse,
                    $publicKeyCredentialCreationOptions,
                    $request,
                    $publicKeyCredentialSource
                )
            );
            return $publicKeyCredentialSource;
        } catch (Throwable $throwable) {
            $this->logger->error('An error occurred', [
                'exception' => $throwable,
            ]);
            $this->eventDispatcher->dispatch(
                $this->createAuthenticatorAttestationResponseValidationFailedEvent(
                    $authenticatorAttestationResponse,
                    $publicKeyCredentialCreationOptions,
                    $request,
                    $throwable
                )
            );
            throw $throwable;
        }
    }

    protected function createAuthenticatorAttestationResponseValidationSucceededEvent(
        AuthenticatorAttestationResponse $authenticatorAttestationResponse,
        PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        ServerRequestInterface|string $request,
        PublicKeyCredentialSource $publicKeyCredentialSource
    ): AuthenticatorAttestationResponseValidationSucceededEvent {
        if ($request instanceof ServerRequestInterface) {
            trigger_deprecation(
                'web-auth/webauthn-lib',
                '4.5.0',
                sprintf(
                    'Passing a %s to the method `createAuthenticatorAttestationResponseValidationSucceededEvent` of the class "%s" is deprecated since 4.5.0 and will be removed in 5.0.0. Please inject the host as a string instead.',
                    ServerRequestInterface::class,
                    self::class
                )
            );
        }
        return new AuthenticatorAttestationResponseValidationSucceededEvent(
            $authenticatorAttestationResponse,
            $publicKeyCredentialCreationOptions,
            $request,
            $publicKeyCredentialSource
        );
    }

    protected function createAuthenticatorAttestationResponseValidationFailedEvent(
        AuthenticatorAttestationResponse $authenticatorAttestationResponse,
        PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        ServerRequestInterface|string $request,
        Throwable $throwable
    ): AuthenticatorAttestationResponseValidationFailedEvent {
        if ($request instanceof ServerRequestInterface) {
            trigger_deprecation(
                'web-auth/webauthn-lib',
                '4.5.0',
                sprintf(
                    'Passing a %s to the method `createAuthenticatorAttestationResponseValidationFailedEvent` of the class "%s" is deprecated since 4.5.0 and will be removed in 5.0.0. Please inject the host as a string instead.',
                    ServerRequestInterface::class,
                    self::class
                )
            );
        }
        return new AuthenticatorAttestationResponseValidationFailedEvent(
            $authenticatorAttestationResponse,
            $publicKeyCredentialCreationOptions,
            $request,
            $throwable
        );
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
            $this->certificateChainValidator?->check($authenticatorCertificates, []);
            return;
        }
        $trustedCertificates = CertificateToolbox::fixPEMStructures(
            $metadataStatement->getAttestationRootCertificates()
        );
        $this->certificateChainValidator?->check($authenticatorCertificates, $trustedCertificates);
    }

    private function checkMetadataStatement(
        PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        AttestationObject $attestationObject
    ): void {
        $attestationStatement = $attestationObject->getAttStmt();
        $attestedCredentialData = $attestationObject->getAuthData()
            ->getAttestedCredentialData();
        $attestedCredentialData !== null || throw AuthenticatorResponseVerificationException::create(
            'No attested credential data found'
        );
        $aaguid = $attestedCredentialData->getAaguid()
            ->__toString();
        if ($publicKeyCredentialCreationOptions->getAttestation() === null || $publicKeyCredentialCreationOptions->getAttestation() === PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE) {
            $this->logger->debug('No attestation is asked.');
            //No attestation is asked. We shall ensure that the data is anonymous.
            if ($aaguid === '00000000-0000-0000-0000-000000000000' && in_array(
                $attestationStatement->getType(),
                [AttestationStatement::TYPE_NONE, AttestationStatement::TYPE_SELF],
                true
            )) {
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
        if (count($metadataStatement->getAttestationTypes()) !== 0) {
            $type = $this->getAttestationType($attestationStatement);
            in_array(
                $type,
                $metadataStatement->getAttestationTypes(),
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
        return match ($attestationStatement->getType()) {
            AttestationStatement::TYPE_BASIC => MetadataStatement::ATTESTATION_BASIC_FULL,
            AttestationStatement::TYPE_SELF => MetadataStatement::ATTESTATION_BASIC_SURROGATE,
            AttestationStatement::TYPE_ATTCA => MetadataStatement::ATTESTATION_ATTCA,
            AttestationStatement::TYPE_ECDAA => MetadataStatement::ATTESTATION_ECDAA,
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

    private function createPublicKeyCredentialSource(
        string $credentialId,
        AttestedCredentialData $attestedCredentialData,
        AttestationObject $attestationObject,
        string $userHandle
    ): PublicKeyCredentialSource {
        $credentialPublicKey = $attestedCredentialData->getCredentialPublicKey();
        $credentialPublicKey !== null || throw AuthenticatorResponseVerificationException::create(
            'Not credential public key available in the attested credential data'
        );
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
            ->value();
        $wasUsed = $authenticationExtensionsClientOutputs->get('appid')
            ->value();
        if (! is_string($appId) || $wasUsed !== true) {
            return $rpId;
        }
        return $appId;
    }
}
