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

use Base64Url\Base64Url;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Webauthn\AttestedCredentialData;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorData;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CredentialRepository;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * @group functional
 * @group Fido2
 */
class PackedAttestationStatementTest extends AbstractTestCase
{
    /**
     * @test
     */
    public function aPackedAttestationCanBeVerified(): void
    {
        $publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity('My Application'),
            new PublicKeyCredentialUserEntity('test@foo.com', random_bytes(64), 'Test PublicKeyCredentialUserEntity'),
            \Safe\base64_decode('32urRB1LDfyfYeU9myCPfrhrvNoVI27//+PWWYVxAISpIm3GqgX+jNudPgvOZy96UPNvEkCWCArW0jtpQZFGAg==', true),
            [
                new PublicKeyCredentialParameters('public-key', PublicKeyCredentialParameters::ALGORITHM_ES256),
            ],
            60000,
            [],
            new AuthenticatorSelectionCriteria(),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
            new AuthenticationExtensionsClientInputs()
        );

        $publicKeyCredential = $this->getPublicKeyCredentialLoader()->load('{"id":"xYw3gEj0LVL83JXz7oKL14XQjh9W1NMFrTALWI-lqXl7ndKW-n8JFYsBCuKbZA3zRAUxAZDHG_tXHsAi6TbO0Q","type":"public-key","rawId":"xYw3gEj0LVL83JXz7oKL14XQjh9W1NMFrTALWI+lqXl7ndKW+n8JFYsBCuKbZA3zRAUxAZDHG/tXHsAi6TbO0Q==","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiIzMnVyUkIxTERmeWZZZVU5bXlDUGZyaHJ2Tm9WSTI3X18tUFdXWVZ4QUlTcEltM0dxZ1gtak51ZFBndk9aeTk2VVBOdkVrQ1dDQXJXMGp0cFFaRkdBZyIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAOkogofSKvV0ma9Ejb3WH44tmXrUhSNK5qg7blgjR1n8AiEAuMsQaAsw27slMfM+wLfe4ozk+Mv8Rxdluhj59hLP4fxjeDVjgVkCwjCCAr4wggGmoAMCAQICBHSG/cIwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMG8xCzAJBgNVBAYTAlNFMRIwEAYDVQQKDAlZdWJpY28gQUIxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDE5NTUwMDM4NDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASVXfOt9yR9MXXv/ZzE8xpOh4664YEJVmFQ+ziLLl9lJ79XQJqlgaUNCsUvGERcChNUihNTyKTlmnBOUjvATevto2wwajAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTATBgsrBgEEAYLlHAIBAQQEAwIFIDAhBgsrBgEEAYLlHAEBBAQSBBD4oBHzjApNFYAGFxEfntx9MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBADFcSIDmmlJ+OGaJvWn9CqhvSeueToVFQVVvqtALOgCKHdwB+Wx29mg2GpHiMsgQp5xjB0ybbnpG6x212FxESJ+GinZD0ipchi7APwPlhIvjgH16zVX44a4e4hOsc6tLIOP71SaMsHuHgCcdH0vg5d2sc006WJe9TXO6fzV+ogjJnYpNKQLmCXoAXE3JBNwKGBIOCvfQDPyWmiiG5bGxYfPty8Z3pnjX+1MDnM2hhr40ulMxlSNDnX/ZSnDyMGIbk8TOQmjTF02UO8auP8k3wt5D1rROIRU9+FCSX5WQYi68RuDrGMZB8P5+byoJqbKQdxn2LmE1oZAyohPAmLcoPO5oYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAHz4oBHzjApNFYAGFxEfntx9AEDFjDeASPQtUvzclfPugovXhdCOH1bU0wWtMAtYj6WpeXud0pb6fwkViwEK4ptkDfNEBTEBkMcb+1cewCLpNs7RpQECAyYgASFYIBECPLnZwCFJ/2Pam0zUQOi4QQAwCKdAZ++36lPi7yvbIlgg4+9scyMxQeQjYGIgli1h5Sh2mlv8BwXwwQKUvbtS+KY="}}');

        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $publicKeyCredential->getResponse());

        $credentialRepository = $this->prophesize(CredentialRepository::class);
        $credentialRepository->has(\Safe\base64_decode('xYw3gEj0LVL83JXz7oKL14XQjh9W1NMFrTALWI+lqXl7ndKW+n8JFYsBCuKbZA3zRAUxAZDHG/tXHsAi6TbO0Q==', true))->willReturn(false);

        $uri = $this->prophesize(UriInterface::class);
        $uri->getHost()->willReturn('localhost');
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getUri()->willReturn($uri->reveal());

        $this->getAuthenticatorAttestationResponseValidator($credentialRepository->reveal())->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request->reveal()
        );

        $this->getAuthenticatorAttestationResponseValidator($credentialRepository->reveal())->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request->reveal()
        );

        $publicKeyCredentialDescriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor(['usb']);

        static::assertEquals(\Safe\base64_decode('xYw3gEj0LVL83JXz7oKL14XQjh9W1NMFrTALWI+lqXl7ndKW+n8JFYsBCuKbZA3zRAUxAZDHG/tXHsAi6TbO0Q==', true), Base64Url::decode($publicKeyCredential->getId()));
        static::assertEquals(\Safe\base64_decode('xYw3gEj0LVL83JXz7oKL14XQjh9W1NMFrTALWI+lqXl7ndKW+n8JFYsBCuKbZA3zRAUxAZDHG/tXHsAi6TbO0Q==', true), $publicKeyCredentialDescriptor->getId());
        static::assertEquals(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $publicKeyCredentialDescriptor->getType());
        static::assertEquals(['usb'], $publicKeyCredentialDescriptor->getTransports());

        /** @var AuthenticatorData $authenticatorData */
        $authenticatorData = $publicKeyCredential->getResponse()->getAttestationObject()->getAuthData();

        static::assertEquals(\Safe\hex2bin('49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763'), $authenticatorData->getRpIdHash());
        static::assertTrue($authenticatorData->isUserPresent());
        static::assertFalse($authenticatorData->isUserVerified());
        static::assertTrue($authenticatorData->hasAttestedCredentialData());
        static::assertEquals(0, $authenticatorData->getReservedForFutureUse1());
        static::assertEquals(0, $authenticatorData->getReservedForFutureUse2());
        static::assertEquals(124, $authenticatorData->getSignCount());
        static::assertInstanceOf(AttestedCredentialData::class, $authenticatorData->getAttestedCredentialData());
        static::assertFalse($authenticatorData->hasExtensions());
    }

    /**
     * @test
     */
    public function aPackedAttestationWithSelfStatementCanBeVerified(): void
    {
        $publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity('My Application'),
            new PublicKeyCredentialUserEntity('test@foo.com', random_bytes(64), 'Test PublicKeyCredentialUserEntity'),
            \Safe\base64_decode('oFUGhUevQHX7J6o4OFau5PbncCATaHwjHDLLzCTpiyw=', true),
            [
                new PublicKeyCredentialParameters('public-key', PublicKeyCredentialParameters::ALGORITHM_ES256),
            ],
            60000,
            [],
            new AuthenticatorSelectionCriteria(),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
            new AuthenticationExtensionsClientInputs()
        );

        $publicKeyCredential = $this->getPublicKeyCredentialLoader()->load('{"id":"AFkzwaxVuCUz4qFPaNAgnYgoZKKTtvGIAaIASAbnlHGy8UktdI_jN0CetpIkiw9--R0AF9a6OJnHD-G4aIWur-Pxj-sI9xDE-AVeQKve","type":"public-key","rawId":"AFkzwaxVuCUz4qFPaNAgnYgoZKKTtvGIAaIASAbnlHGy8UktdI/jN0CetpIkiw9++R0AF9a6OJnHD+G4aIWur+Pxj+sI9xDE+AVeQKve","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJvRlVHaFVldlFIWDdKNm80T0ZhdTVQYm5jQ0FUYUh3akhETEx6Q1RwaXl3Iiwib3JpZ2luIjoiaHR0cHM6Ly9zcG9ta3ktd2ViYXV0aG4uaGVyb2t1YXBwLmNvbSIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ==","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgAMCQZYRl2cA+ab2MB3OGBCbq3j62rSubwhaCVSHJvKMCIQD0mMLs/5jjwd0KxYzb9/iM15T1gJ3L1Uv5BnMtQtVYBmhhdXRoRGF0YVjStIXbbgSILsWHHbR0Fjkl96X4ROZYLvVtOopBWCQoAqpFXE8bBwAAAAAAAAAAAAAAAAAAAAAATgBZM8GsVbglM+KhT2jQIJ2IKGSik7bxiAGiAEgG55RxsvFJLXSP4zdAnraSJIsPfvkdABfWujiZxw/huGiFrq/j8Y/rCPcQxPgFXkCr3qUBAgMmIAEhWCBOSwRVQxXPb76nvmQ2HQ8i5Bin8M4zfZCqIlKXrcxxmyJYIOFCAZ9+rRhklvn1nk2TahaCvpH96emEuKoGxpEObvQg"}}');

        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $publicKeyCredential->getResponse());

        $credentialRepository = $this->prophesize(CredentialRepository::class);
        $credentialRepository->has(\Safe\base64_decode('AFkzwaxVuCUz4qFPaNAgnYgoZKKTtvGIAaIASAbnlHGy8UktdI/jN0CetpIkiw9++R0AF9a6OJnHD+G4aIWur+Pxj+sI9xDE+AVeQKve', true))->willReturn(false);

        $uri = $this->prophesize(UriInterface::class);
        $uri->getHost()->willReturn('spomky-webauthn.herokuapp.com');
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getUri()->willReturn($uri->reveal());

        $this->getAuthenticatorAttestationResponseValidator($credentialRepository->reveal())->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request->reveal()
        );

        $this->getAuthenticatorAttestationResponseValidator($credentialRepository->reveal())->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request->reveal()
        );

        $publicKeyCredentialDescriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor(['usb']);

        static::assertEquals(\Safe\base64_decode('AFkzwaxVuCUz4qFPaNAgnYgoZKKTtvGIAaIASAbnlHGy8UktdI/jN0CetpIkiw9++R0AF9a6OJnHD+G4aIWur+Pxj+sI9xDE+AVeQKve', true), Base64Url::decode($publicKeyCredential->getId()));
        static::assertEquals(\Safe\base64_decode('AFkzwaxVuCUz4qFPaNAgnYgoZKKTtvGIAaIASAbnlHGy8UktdI/jN0CetpIkiw9++R0AF9a6OJnHD+G4aIWur+Pxj+sI9xDE+AVeQKve', true), $publicKeyCredentialDescriptor->getId());
        static::assertEquals(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $publicKeyCredentialDescriptor->getType());
        static::assertEquals(['usb'], $publicKeyCredentialDescriptor->getTransports());

        /** @var AuthenticatorData $authenticatorData */
        $authenticatorData = $publicKeyCredential->getResponse()->getAttestationObject()->getAuthData();

        static::assertEquals(\Safe\hex2bin('b485db6e04882ec5871db474163925f7a5f844e6582ef56d3a8a4158242802aa'), $authenticatorData->getRpIdHash());
        static::assertTrue($authenticatorData->isUserPresent());
        static::assertTrue($authenticatorData->isUserVerified());
        static::assertTrue($authenticatorData->hasAttestedCredentialData());
        static::assertEquals(0, $authenticatorData->getReservedForFutureUse1());
        static::assertEquals(0, $authenticatorData->getReservedForFutureUse2());
        static::assertEquals(1548688135, $authenticatorData->getSignCount());
        static::assertInstanceOf(AttestedCredentialData::class, $authenticatorData->getAttestedCredentialData());
        static::assertFalse($authenticatorData->hasExtensions());
    }
}
