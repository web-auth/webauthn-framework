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

namespace Webauthn\Bundle\Tests\Functional\Attestation;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * @group functional
 */
class ConformanceTest extends KernelTestCase
{
    /**
     * @test
     */
    public function anAttestationResponseCanBeLoadedAndVerified(): void
    {
        self::bootKernel();

        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::createFromString('{"status":"ok","errorMessage":"","rp":{"name":"Webauthn Demo"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-43},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39}],"challenge":"rmQ5Q9hCCejS4GecSq66wzyg5TpIeReSURyc-r3P1lo","attestation":"direct","user":{"name":"aHUNZQVEGigxccbPuCqy","id":"YTdiMzcwZTctYjkyYS00ZGIxLTllMjQtYjBkNWRiN2E2Njk5","displayName":"Marivel Placencia"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":60000}');
        $publicKeyCredential = self::$kernel->getContainer()->get(PublicKeyCredentialLoader::class)->load('{"id":"BEGIYTmVmGEGHbBFLYtzz1aKmTjBfC36h9p_P4AjGfU","rawId":"BEGIYTmVmGEGHbBFLYtzz1aKmTjBfC36h9p_P4AjGfU","response":{"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzkBAWNzaWdZAQCKCi0QYC8lgqDD1FDjXvYvagDry4M4eMwTknLOewlUNKsMzY0r7gdOg2C2NsuwXU1efbBgnDqfTd6UkO8WehwP8wvJnVyPB179r508PSn2_5W5BFAV_XevtOZ3oPAnjMCsljxL1fhKws_WS6YHtq2-X0ZM8FZ-DuxO0mNbxONUHrnSsnrDOLuilvFzZleSifAR0F1Q3GDfZ7Kz57hEfNwszhhIeQN7YoM-6ZS-MbV62AqQaD_wTXjcilL9OECLjTjMkn9LtFxhVB4YtwnPrcYl3T78YDGbuEghcTl_58aABk25IPA-CSTNwTjOLzai-H-t2P7s_NBe3UNaTggMKBBXaGF1dGhEYXRhWQFnlgTqgoJOmKStoUtEYtDXOo7EaRMNqRsZMHRZIp90o1lBAAAAk1nBGOoYjE3PmIG4sFir8vEAIARBiGE5lZhhBh2wRS2Lc89Wipk4wXwt-ofafz-AIxn1pAEDAzkBASBZAQDr5pNwn1gTSBIs6SY52LJk2ZCBaKL7rSJFlaluQfJipoWotpi3cDpFfCYb2JepnTtQwDIurIzvtS69fbJBZU9S58zK_TH-xWzgn5F23doT_D6KLAyL3r_zCuV2vO1OE7rvZDjnvgKN1L9VEadbDmuWaa9wxa6MG3nk4kTUDVFUFIkNbkZTAgS_9WSB9X5pZRh8_7IaL0RXWx0dNCT5Z-kXKcnokN9Bsh_wCa11Fx6tmUkDS9JMjwRM_kIghAU4-VZmGWL71j_li6PAeXpJR8JM-zQ6IerEZozBN7b9IaL6jVGtolJDe4pXcFZs1GUmsr2bC-FuVl5oqyVYcz1H_AQ5IUMBAAE","clientDataJSON":"eyJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLnNwb21reS1sYWJzLmNvbSIsImNoYWxsZW5nZSI6InJtUTVROWhDQ2VqUzRHZWNTcTY2d3p5ZzVUcEllUmVTVVJ5Yy1yM1AxbG8iLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"},"type":"public-key"}');

        $descriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor();
        static::assertEquals(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $descriptor->getType());
        static::assertEquals(hex2bin('0441886139959861061db0452d8b73cf568a9938c17c2dfa87da7f3f802319f5'), $descriptor->getId());
        static::assertEquals([], $descriptor->getTransports());

        $response = $publicKeyCredential->getResponse();
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);
        static::assertEquals(AttestationStatement::TYPE_SELF, $response->getAttestationObject()->getAttStmt()->getType());
        static::assertInstanceOf(EmptyTrustPath::class, $response->getAttestationObject()->getAttStmt()->getTrustPath());

        $uri = $this->prophesize(UriInterface::class);
        $uri->getHost()->willReturn('webauthn.spomky-labs.com');
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getUri()->willReturn($uri->reveal());

        self::$kernel->getContainer()->get(AuthenticatorAttestationResponseValidator::class)->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request->reveal()
        );
    }

    /**
     * @test
     */
    public function aPublicKeyCredentialCreationOptionsCanBeCreatedFromProfile(): void
    {
        self::bootKernel();

        /** @var PublicKeyCredentialCreationOptionsFactory $factory */
        $factory = self::$kernel->getContainer()->get(PublicKeyCredentialCreationOptionsFactory::class);
        $options = $factory->create(
            'foo',
            new PublicKeyCredentialUserEntity('test@foo.com', random_bytes(64), 'Test PublicKeyCredentialUserEntity')
        );

        static::assertEquals(64, mb_strlen($options->getChallenge(), '8bit'));
        static::assertInstanceOf(AuthenticationExtensionsClientInputs::class, $options->getExtensions());
        static::assertEquals([], $options->getExcludeCredentials());
        static::assertEquals(2, \count($options->getPubKeyCredParams()));
        static::assertEquals('direct', $options->getAttestation());
        static::assertEquals(30000, $options->getTimeout());
        static::assertInstanceOf(PublicKeyCredentialRpEntity::class, $options->getRp());
        static::assertInstanceOf(PublicKeyCredentialUserEntity::class, $options->getUser());
        static::assertInstanceOf(AuthenticatorSelectionCriteria::class, $options->getAuthenticatorSelection());
    }
}
