<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2021 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Tests\Functional\Assertion;

use Base64Url\Base64Url;
use function Safe\base64_decode;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\Tests\MockedRequestTrait;

/**
 * @group functional
 *
 * @internal
 */
class AssertionTest extends WebTestCase
{
    use MockedRequestTrait;

    /**
     * @test
     */
    public function anAssertionResponseCanBeLoadedAndVerified(): void
    {
        self::bootKernel();

        $publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions::create(base64_decode('G0JbLLndef3a0Iy3S2sSQA8uO4SO/ze6FZMAuPI6+xI=', true))
            ->setTimeout(60000)
            ->setRpId('localhost')
            ->setUserVerification(PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED)
            ->allowCredential(new PublicKeyCredentialDescriptor(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                Base64Url::decode('eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w')
            ))
        ;

        $publicKeyCredential = self::$kernel->getContainer()->get(PublicKeyCredentialLoader::class)->load('{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"public-key","rawId":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MBAAAAew==","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ==","signature":"MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=","userHandle":null}}');

        $descriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor();
        static::assertEquals(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $descriptor->getType());
        static::assertEquals(base64_decode('eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==', true), $descriptor->getId());
        static::assertEquals([], $descriptor->getTransports());

        $response = $publicKeyCredential->getResponse();
        static::assertInstanceOf(AuthenticatorAssertionResponse::class, $response);
        static::assertNull($response->getUserHandle());

        $request = $this->createRequestWithHost('localhost');

        self::$kernel->getContainer()->get(AuthenticatorAssertionResponseValidator::class)->check(
            $publicKeyCredential->getRawId(),
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialRequestOptions,
            $request,
            'foo'
        );
    }

    /**
     * @test
     */
    public function aPublicKeyCredentialCreationOptionsCanBeCreatedFromProfile(): void
    {
        self::bootKernel();

        $allowedCredentials = [
            new PublicKeyCredentialDescriptor(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                Base64Url::decode('eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w')
            ),
        ];

        /** @var PublicKeyCredentialRequestOptionsFactory $factory */
        $factory = self::$kernel->getContainer()->get(PublicKeyCredentialRequestOptionsFactory::class);
        $options = $factory->create('default', $allowedCredentials);

        static::assertEquals(30000, $options->getTimeout());
        static::assertEquals('localhost', $options->getRpId());
        static::assertEquals($allowedCredentials, $options->getAllowCredentials());
        static::assertEquals('preferred', $options->getUserVerification());
        static::assertInstanceOf(AuthenticationExtensionsClientInputs::class, $options->getExtensions());
    }
}
