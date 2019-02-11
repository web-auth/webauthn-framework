<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Tests\Functional;

use CBOR\Decoder;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\Tag\TagObjectManager;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Algorithm\Signature\EdDSA\EdDSA;
use Cose\Algorithm\Signature\RSA\RS1;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\RSA\RS384;
use Cose\Algorithm\Signature\RSA\RS512;
use Http\Client\HttpClient;
use Http\Mock\Client;
use PHPUnit\Framework\TestCase;
use Webauthn\AttestationStatement\AndroidSafetyNetAttestationStatementSupport;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CredentialRepository;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\TokenBinding\IgnoreTokenBindingHandler;
use Webauthn\TokenBinding\TokenBindingNotSupportedHandler;

/**
 * @group functional
 * @group Fido2
 */
abstract class AbstractTestCase extends TestCase
{
    /**
     * @var PublicKeyCredentialLoader|null
     */
    private $publicKeyCredentialLoader;

    protected function getPublicKeyCredentialLoader(): PublicKeyCredentialLoader
    {
        if (!$this->publicKeyCredentialLoader) {
            $this->publicKeyCredentialLoader = new PublicKeyCredentialLoader(
                $this->getAttestationObjectLoader(),
                $this->getDecoder()
            );
        }

        return $this->publicKeyCredentialLoader;
    }

    /**
     * @var AuthenticatorAttestationResponseValidator|null
     */
    private $authenticatorAttestationResponseValidator;

    protected function getAuthenticatorAttestationResponseValidator(CredentialRepository $credentialRepository, ?HttpClient $client = null): AuthenticatorAttestationResponseValidator
    {
        if (!$this->authenticatorAttestationResponseValidator) {
            $this->authenticatorAttestationResponseValidator = new AuthenticatorAttestationResponseValidator(
                $this->getAttestationStatementSupportManager($client),
                $credentialRepository,
                new IgnoreTokenBindingHandler(),
                new ExtensionOutputCheckerHandler()
            );
        }

        return $this->authenticatorAttestationResponseValidator;
    }

    /**
     * @var AuthenticatorAssertionResponseValidator|null
     */
    private $authenticatorAssertionResponseValidator;

    protected function getAuthenticatorAssertionResponseValidator(CredentialRepository $credentialRepository): AuthenticatorAssertionResponseValidator
    {
        if (!$this->authenticatorAssertionResponseValidator) {
            $this->authenticatorAssertionResponseValidator = new AuthenticatorAssertionResponseValidator(
                $credentialRepository,
                $this->getDecoder(),
                new TokenBindingNotSupportedHandler(),
                new ExtensionOutputCheckerHandler()
            );
        }

        return $this->authenticatorAssertionResponseValidator;
    }

    /**
     * @var Decoder|null
     */
    private $decoder;

    private function getDecoder(): Decoder
    {
        if (!$this->decoder) {
            $this->decoder = new Decoder(
                new TagObjectManager(),
                new OtherObjectManager()
            );
        }

        return $this->decoder;
    }

    private function getAttestationStatementSupportManager(?HttpClient $client = null): AttestationStatementSupportManager
    {
        $attestationStatementSupportManager = new AttestationStatementSupportManager();
        $attestationStatementSupportManager->add(new NoneAttestationStatementSupport());
        $attestationStatementSupportManager->add(new AndroidSafetyNetAttestationStatementSupport(
            $client ?? new Client(),
            'api_key'
        ));
        $attestationStatementSupportManager->add(new FidoU2FAttestationStatementSupport(
            $this->getDecoder()
        ));
        $attestationStatementSupportManager->add(new PackedAttestationStatementSupport(
            $this->getDecoder(),
            $this->getAlgorithmManager()
        ));

        return $attestationStatementSupportManager;
    }

    /**
     * @var AttestationObjectLoader|null
     */
    private $algorithmManager;

    private function getAlgorithmManager(): Manager
    {
        if (!$this->algorithmManager) {
            $this->algorithmManager = new Manager();
            $this->algorithmManager->add(new ES256());
            $this->algorithmManager->add(new ES384());
            $this->algorithmManager->add(new ES512());
            $this->algorithmManager->add(new RS1());
            $this->algorithmManager->add(new RS256());
            $this->algorithmManager->add(new RS384());
            $this->algorithmManager->add(new RS512());
            $this->algorithmManager->add(new EdDSA());
        }

        return $this->algorithmManager;
    }

    /**
     * @var AttestationObjectLoader|null
     */
    private $attestationObjectLoader;

    private function getAttestationObjectLoader(): AttestationObjectLoader
    {
        if (!$this->attestationObjectLoader) {
            $this->attestationObjectLoader = new AttestationObjectLoader(
                $this->getAttestationStatementSupportManager(),
                $this->getDecoder()
            );
        }

        return $this->attestationObjectLoader;
    }
}
