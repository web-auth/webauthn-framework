<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Easy;

use Assert\Assertion;
use CBOR\Decoder;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\Tag\TagObjectManager;
use Cose\Algorithm\Algorithm;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA;
use Cose\Algorithm\Signature\EdDSA;
use Cose\Algorithm\Signature\RSA;
use Cose\Algorithms;
use Psr\Http\Message\ServerRequestInterface;
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
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TokenBinding\TokenBindingNotSupportedHandler;

class Server
{
    /**
     * @var PublicKeyCredentialRpEntity
     */
    private $rpEntity;

    /**
     * @var int
     */
    public $timeout = 60000;

    /**
     * @var PublicKeyCredentialParameters[]
     */
    private $publicKeyCredentialParametersList;

    /**
     * @var Manager
     */
    private $coseAlgorithmManager;

    /**
     * @var PublicKeyCredentialSourceRepository
     */
    private $publicKeyCredentialSourceRepository;

    /**
     * @var Decoder
     */
    private $decoder;

    /**
     * @var TokenBindingNotSupportedHandler
     */
    private $tokenBindingHandler;

    /**
     * @var AttestationStatementSupportManager
     */
    private $attestationStatementSupportManager;

    /**
     * @var AttestationObjectLoader
     */
    private $attestationObjectLoader;

    /**
     * @var ExtensionOutputCheckerHandler
     */
    private $extensionOutputCheckerHandler;

    /**
     * @var PublicKeyCredentialLoader
     */
    private $publicKeyCredentialLoader;

    public function __construct(PublicKeyCredentialRpEntity $relayingParty, PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository)
    {
        $this->rpEntity = $relayingParty;

        $this->coseAlgorithmManager = new Manager();
        $this->coseAlgorithmManager->add(new RSA\RS1());
        $this->coseAlgorithmManager->add(new RSA\RS256());
        $this->coseAlgorithmManager->add(new RSA\RS384());
        $this->coseAlgorithmManager->add(new RSA\RS512());
        $this->coseAlgorithmManager->add(new RSA\PS256());
        $this->coseAlgorithmManager->add(new RSA\PS384());
        $this->coseAlgorithmManager->add(new RSA\PS512());
        $this->coseAlgorithmManager->add(new ECDSA\ES256());
        $this->coseAlgorithmManager->add(new ECDSA\ES256K());
        $this->coseAlgorithmManager->add(new ECDSA\ES384());
        $this->coseAlgorithmManager->add(new ECDSA\ES512());
        $this->coseAlgorithmManager->add(new EdDSA\ED512());

        $this->publicKeyCredentialParametersList = [
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_RS1),
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_RS256),
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_RS384),
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_RS512),
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_PS256),
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_PS384),
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_PS512),
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_ES256),
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_ES256K),
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_ES384),
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_ES512),
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_ED256),
        ];
        $this->publicKeyCredentialSourceRepository = $publicKeyCredentialSourceRepository;

        $otherObjectManager = new OtherObjectManager();
        $tagObjectManager = new TagObjectManager();
        $this->decoder = new Decoder($tagObjectManager, $otherObjectManager);

        $this->tokenBindingHandler = new TokenBindingNotSupportedHandler();

        $this->attestationStatementSupportManager = new AttestationStatementSupportManager();
        $this->attestationStatementSupportManager->add(new NoneAttestationStatementSupport());
        $this->attestationStatementSupportManager->add(new FidoU2FAttestationStatementSupport());
        $this->attestationStatementSupportManager->add(new AndroidSafetyNetAttestationStatementSupport());
        $this->attestationStatementSupportManager->add(new AndroidKeyAttestationStatementSupport());
        $this->attestationStatementSupportManager->add(new TPMAttestationStatementSupport());
        $this->attestationStatementSupportManager->add(new PackedAttestationStatementSupport(null, $this->coseAlgorithmManager));

        $this->attestationObjectLoader = new AttestationObjectLoader($this->attestationStatementSupportManager, $this->decoder);
        $this->publicKeyCredentialLoader = new PublicKeyCredentialLoader($this->attestationObjectLoader, $this->decoder);
        $this->extensionOutputCheckerHandler = new ExtensionOutputCheckerHandler();
    }

    public function setTokenBindingHandler(TokenBindingNotSupportedHandler $tokenBindingHandler): void
    {
        $this->tokenBindingHandler = $tokenBindingHandler;
    }

    public function addAlgorithm(Algorithm $algorithm): void
    {
        $this->coseAlgorithmManager->add($algorithm);
    }

    public function setExtensionOutputCheckerHandler(ExtensionOutputCheckerHandler $extensionOutputCheckerHandler): void
    {
        $this->extensionOutputCheckerHandler = $extensionOutputCheckerHandler;
    }

    /**
     * @param PublicKeyCredentialDescriptor[] $excludedPublicKeyDescriptors
     */
    public function generatePublicKeyCredentialCreationOptions(PublicKeyCredentialUserEntity $userEntity, ?string $attestationMode = PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE, array $excludedPublicKeyDescriptors = [], ?AuthenticatorSelectionCriteria $criteria = null, ?AuthenticationExtensionsClientInputs $extensions = null): PublicKeyCredentialCreationOptions
    {
        $criteria = $criteria ?? new AuthenticatorSelectionCriteria();
        $extensions = $extensions ?? new AuthenticationExtensionsClientInputs();
        $challenge = random_bytes(32);

        return new PublicKeyCredentialCreationOptions(
            $this->rpEntity,
            $userEntity,
            $challenge,
            $this->publicKeyCredentialParametersList,
            $this->timeout,
            $excludedPublicKeyDescriptors,
            $criteria,
            $attestationMode,
            $extensions
        );
    }

    public function loadAndCheckAttestationResponse(string $data, PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions, ServerRequestInterface $serverRequest): PublicKeyCredentialSource
    {
        $publicKeyCredential = $this->publicKeyCredentialLoader->load($data);
        $authenticatorResponse = $publicKeyCredential->getResponse();
        Assertion::isInstanceOf($authenticatorResponse, AuthenticatorAttestationResponse::class, 'Not an authenticator attestation response');

        $authenticatorAttestationResponseValidator = new AuthenticatorAttestationResponseValidator(
            $this->attestationStatementSupportManager,
            $this->publicKeyCredentialSourceRepository,
            $this->tokenBindingHandler,
            $this->extensionOutputCheckerHandler
        );
        $authenticatorAttestationResponseValidator->check($authenticatorResponse, $publicKeyCredentialCreationOptions, $serverRequest);

        return PublicKeyCredentialSource::createFromPublicKeyCredential($publicKeyCredential, $publicKeyCredentialCreationOptions->getUser()->getId());
    }
}
