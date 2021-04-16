<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn;

use Assert\Assertion;
use Cose\Algorithm\Algorithm;
use Cose\Algorithm\ManagerFactory;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES256K;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Algorithm\Signature\RSA;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS384;
use Cose\Algorithm\Signature\RSA\PS512;
use Cose\Algorithm\Signature\RSA\RS1;
use Cose\Algorithm\Signature\RSA\RS384;
use Cose\Algorithm\Signature\RSA\RS512;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Webauthn\AttestationStatement\AndroidSafetyNetAttestationStatementSupport;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\Counter\CounterChecker;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\TokenBinding\IgnoreTokenBindingHandler;
use Webauthn\TokenBinding\TokenBindingHandler;

class Server
{
    public ?int $timeout = null;

    public int $challengeSize = 32;

    private ManagerFactory $coseAlgorithmManagerFactory;

    private TokenBindingHandler $tokenBindingHandler;

    private ExtensionOutputCheckerHandler $extensionOutputCheckerHandler;

    /**
     * @var string[]
     */
    private array $selectedAlgorithms;

    private ?MetadataStatementRepository $metadataStatementRepository = null;

    private ?ClientInterface $httpClient = null;

    private ?string $googleApiKey = null;

    private ?RequestFactoryInterface $requestFactory = null;

    private ?CounterChecker $counterChecker = null;

    private LoggerInterface $logger;

    /**
     * @var string[]
     */
    private array $securedRelyingPartyId = [];

    public function __construct(private PublicKeyCredentialRpEntity $rpEntity, private PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository)
    {
        $this->logger = new NullLogger();

        $this->coseAlgorithmManagerFactory = new ManagerFactory();
        $this->coseAlgorithmManagerFactory->add('RS1', new RS1());
        $this->coseAlgorithmManagerFactory->add('RS256', new RSA\RS256());
        $this->coseAlgorithmManagerFactory->add('RS384', new RS384());
        $this->coseAlgorithmManagerFactory->add('RS512', new RS512());
        $this->coseAlgorithmManagerFactory->add('PS256', new PS256());
        $this->coseAlgorithmManagerFactory->add('PS384', new PS384());
        $this->coseAlgorithmManagerFactory->add('PS512', new PS512());
        $this->coseAlgorithmManagerFactory->add('ES256', new ES256());
        $this->coseAlgorithmManagerFactory->add('ES256K', new ES256K());
        $this->coseAlgorithmManagerFactory->add('ES384', new ES384());
        $this->coseAlgorithmManagerFactory->add('ES512', new ES512());
        $this->coseAlgorithmManagerFactory->add('Ed25519', new Ed25519());

        $this->selectedAlgorithms = ['RS256', 'RS512', 'PS256', 'PS512', 'ES256', 'ES512', 'Ed25519'];
        $this->tokenBindingHandler = IgnoreTokenBindingHandler::create();
        $this->extensionOutputCheckerHandler = ExtensionOutputCheckerHandler::create();
    }

    public static function create(PublicKeyCredentialRpEntity $rpEntity, PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository): self
    {
        return new self($rpEntity, $publicKeyCredentialSourceRepository);
    }

    public function setMetadataStatementRepository(MetadataStatementRepository $metadataStatementRepository): self
    {
        $this->metadataStatementRepository = $metadataStatementRepository;

        return $this;
    }

    /**
     * @param string[] $selectedAlgorithms
     */
    public function setSelectedAlgorithms(array $selectedAlgorithms): self
    {
        $this->selectedAlgorithms = $selectedAlgorithms;

        return $this;
    }

    public function setTokenBindingHandler(TokenBindingHandler $tokenBindingHandler): self
    {
        $this->tokenBindingHandler = $tokenBindingHandler;

        return $this;
    }

    public function addAlgorithm(string $alias, Algorithm $algorithm): self
    {
        $this->coseAlgorithmManagerFactory->add($alias, $algorithm);
        $this->selectedAlgorithms[] = $alias;
        $this->selectedAlgorithms = array_unique($this->selectedAlgorithms);

        return $this;
    }

    public function setExtensionOutputCheckerHandler(ExtensionOutputCheckerHandler $extensionOutputCheckerHandler): self
    {
        $this->extensionOutputCheckerHandler = $extensionOutputCheckerHandler;

        return $this;
    }

    /**
     * @param string[] $securedRelyingPartyId
     */
    public function setSecuredRelyingPartyId(array $securedRelyingPartyId): self
    {
        Assertion::allString($securedRelyingPartyId, 'Invalid list. Shall be a list of strings');
        $this->securedRelyingPartyId = $securedRelyingPartyId;

        return $this;
    }

    /**
     * @param PublicKeyCredentialDescriptor[] $excludedPublicKeyDescriptors
     */
    public function generatePublicKeyCredentialCreationOptions(PublicKeyCredentialUserEntity $userEntity, ?string $attestationMode = null, array $excludedPublicKeyDescriptors = [], ?AuthenticatorSelectionCriteria $criteria = null, ?AuthenticationExtensionsClientInputs $extensions = null): PublicKeyCredentialCreationOptions
    {
        $coseAlgorithmManager = $this->coseAlgorithmManagerFactory->create($this->selectedAlgorithms);
        $publicKeyCredentialParametersList = [];
        foreach ($coseAlgorithmManager->all() as $algorithm) {
            $publicKeyCredentialParametersList[] = PublicKeyCredentialParameters::create(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                $algorithm::identifier()
            );
        }
        $criteria = $criteria ?? AuthenticatorSelectionCriteria::create();
        $extensions = $extensions ?? AuthenticationExtensionsClientInputs::create();
        $challenge = random_bytes($this->challengeSize);

        return PublicKeyCredentialCreationOptions
            ::create(
                $this->rpEntity,
                $userEntity,
                $challenge,
                $publicKeyCredentialParametersList
            )
                ->excludeCredentials($excludedPublicKeyDescriptors)
                ->setAuthenticatorSelection($criteria)
                ->setAttestation($attestationMode ?? PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE)
                ->setExtensions($extensions)
                ->setTimeout($this->timeout)
        ;
    }

    /**
     * @param PublicKeyCredentialDescriptor[] $allowedPublicKeyDescriptors
     */
    public function generatePublicKeyCredentialRequestOptions(?string $userVerification = null, array $allowedPublicKeyDescriptors = [], ?AuthenticationExtensionsClientInputs $extensions = null): PublicKeyCredentialRequestOptions
    {
        return PublicKeyCredentialRequestOptions
            ::create(random_bytes($this->challengeSize))
                ->setRpId($this->rpEntity->getId())
                ->setUserVerification($userVerification ?? PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED)
                ->allowCredentials($allowedPublicKeyDescriptors)
                ->setTimeout($this->timeout)
                ->setExtensions($extensions ?? AuthenticationExtensionsClientInputs::create())
        ;
    }

    public function loadAndCheckAttestationResponse(string $data, PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions, ServerRequestInterface $serverRequest): PublicKeyCredentialSource
    {
        $attestationStatementSupportManager = $this->getAttestationStatementSupportManager();
        $attestationObjectLoader = AttestationObjectLoader::create($attestationStatementSupportManager)
            ->setLogger($this->logger)
        ;
        $publicKeyCredentialLoader = PublicKeyCredentialLoader::create($attestationObjectLoader)
            ->setLogger($this->logger)
        ;

        $publicKeyCredential = $publicKeyCredentialLoader->load($data);
        $authenticatorResponse = $publicKeyCredential->getResponse();
        Assertion::isInstanceOf($authenticatorResponse, AuthenticatorAttestationResponse::class, 'Not an authenticator attestation response');

        $authenticatorAttestationResponseValidator = AuthenticatorAttestationResponseValidator::create(
            $attestationStatementSupportManager,
            $this->publicKeyCredentialSourceRepository,
            $this->tokenBindingHandler,
            $this->extensionOutputCheckerHandler
        )
            ->setMetadataStatementRepository($this->metadataStatementRepository)
            ->setLogger($this->logger)
        ;

        return $authenticatorAttestationResponseValidator->check($authenticatorResponse, $publicKeyCredentialCreationOptions, $serverRequest, $this->securedRelyingPartyId);
    }

    public function loadAndCheckAssertionResponse(string $data, PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions, ?PublicKeyCredentialUserEntity $userEntity, ServerRequestInterface $serverRequest): PublicKeyCredentialSource
    {
        $attestationStatementSupportManager = $this->getAttestationStatementSupportManager();
        $attestationObjectLoader = AttestationObjectLoader::create($attestationStatementSupportManager)
            ->setLogger($this->logger)
        ;
        $publicKeyCredentialLoader = PublicKeyCredentialLoader::create($attestationObjectLoader)
            ->setLogger($this->logger)
        ;

        $publicKeyCredential = $publicKeyCredentialLoader->load($data);
        $authenticatorResponse = $publicKeyCredential->getResponse();
        Assertion::isInstanceOf($authenticatorResponse, AuthenticatorAssertionResponse::class, 'Not an authenticator assertion response');

        $authenticatorAssertionResponseValidator = AuthenticatorAssertionResponseValidator::create(
            $this->publicKeyCredentialSourceRepository,
            $this->tokenBindingHandler,
            $this->extensionOutputCheckerHandler,
            $this->coseAlgorithmManagerFactory->create($this->selectedAlgorithms)
        )
            ->setCounterChecker($this->counterChecker)
            ->setLogger($this->logger)
        ;

        return $authenticatorAssertionResponseValidator->check(
            $publicKeyCredential->getRawId(),
            $authenticatorResponse,
            $publicKeyCredentialRequestOptions,
            $serverRequest,
            null !== $userEntity ? $userEntity->getId() : null,
            $this->securedRelyingPartyId
        );
    }

    public function setCounterChecker(CounterChecker $counterChecker): self
    {
        $this->counterChecker = $counterChecker;

        return $this;
    }

    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;

        return $this;
    }

    public function enforceAndroidSafetyNetVerification(ClientInterface $client, string $apiKey, RequestFactoryInterface $requestFactory): self
    {
        $this->httpClient = $client;
        $this->googleApiKey = $apiKey;
        $this->requestFactory = $requestFactory;

        return $this;
    }

    private function getAttestationStatementSupportManager(): AttestationStatementSupportManager
    {
        $attestationStatementSupportManager = AttestationStatementSupportManager::create();
        if (class_exists(RS256::class) && class_exists(JWKFactory::class)) {
            $androidSafetyNetAttestationStatementSupport = AndroidSafetyNetAttestationStatementSupport::create();
            if (null !== $this->httpClient && null !== $this->googleApiKey && null !== $this->requestFactory) {
                $androidSafetyNetAttestationStatementSupport
                    ->enableApiVerification($this->httpClient, $this->googleApiKey, $this->requestFactory)
                    ->setLeeway(2000)
                    ->setMaxAge(60000)
                ;
            }
            $attestationStatementSupportManager->add($androidSafetyNetAttestationStatementSupport);
        }
        $coseAlgorithmManager = $this->coseAlgorithmManagerFactory->create($this->selectedAlgorithms);
        $attestationStatementSupportManager
            ->add(NoneAttestationStatementSupport::create())
            ->add(FidoU2FAttestationStatementSupport::create())
            ->add(AndroidKeyAttestationStatementSupport::create())
            ->add(TPMAttestationStatementSupport::create())
            ->add(PackedAttestationStatementSupport::create($coseAlgorithmManager))
        ;

        return $attestationStatementSupportManager;
    }
}
