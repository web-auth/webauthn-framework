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

namespace Webauthn\Bundle\Tests\Functional\Attestation;

use Cose\Algorithms;
use Prophecy\PhpUnit\ProphecyTrait;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use function Safe\base64_decode;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * @group functional
 *
 * @internal
 */
class PackedAttestationStatementTest extends KernelTestCase
{
    use ProphecyTrait;

    /**
     * @test
     */
    public function aPackedAttestationWithSelfStatementCanBeVerified(): void
    {
        self::bootKernel();

        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions
            ::create(
                new PublicKeyCredentialRpEntity('My Application'),
                new PublicKeyCredentialUserEntity('test@foo.com', random_bytes(64), 'Test PublicKeyCredentialUserEntity'),
                base64_decode('oFUGhUevQHX7J6o4OFau5PbncCATaHwjHDLLzCTpiyw=', true),
                [new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_ES256)]
            )
                ->setAttestation(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT)
        ;

        $publicKeyCredential = self::$kernel->getContainer()->get(PublicKeyCredentialLoader::class)->load('{"id":"AFkzwaxVuCUz4qFPaNAgnYgoZKKTtvGIAaIASAbnlHGy8UktdI_jN0CetpIkiw9--R0AF9a6OJnHD-G4aIWur-Pxj-sI9xDE-AVeQKve","type":"public-key","rawId":"AFkzwaxVuCUz4qFPaNAgnYgoZKKTtvGIAaIASAbnlHGy8UktdI/jN0CetpIkiw9++R0AF9a6OJnHD+G4aIWur+Pxj+sI9xDE+AVeQKve","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJvRlVHaFVldlFIWDdKNm80T0ZhdTVQYm5jQ0FUYUh3akhETEx6Q1RwaXl3Iiwib3JpZ2luIjoiaHR0cHM6Ly9zcG9ta3ktd2ViYXV0aG4uaGVyb2t1YXBwLmNvbSIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ==","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgAMCQZYRl2cA+ab2MB3OGBCbq3j62rSubwhaCVSHJvKMCIQD0mMLs/5jjwd0KxYzb9/iM15T1gJ3L1Uv5BnMtQtVYBmhhdXRoRGF0YVjStIXbbgSILsWHHbR0Fjkl96X4ROZYLvVtOopBWCQoAqpFXE8bBwAAAAAAAAAAAAAAAAAAAAAATgBZM8GsVbglM+KhT2jQIJ2IKGSik7bxiAGiAEgG55RxsvFJLXSP4zdAnraSJIsPfvkdABfWujiZxw/huGiFrq/j8Y/rCPcQxPgFXkCr3qUBAgMmIAEhWCBOSwRVQxXPb76nvmQ2HQ8i5Bin8M4zfZCqIlKXrcxxmyJYIOFCAZ9+rRhklvn1nk2TahaCvpH96emEuKoGxpEObvQg"}}');

        $descriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor();
        static::assertEquals(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $descriptor->getType());
        static::assertEquals(base64_decode('AFkzwaxVuCUz4qFPaNAgnYgoZKKTtvGIAaIASAbnlHGy8UktdI/jN0CetpIkiw9++R0AF9a6OJnHD+G4aIWur+Pxj+sI9xDE+AVeQKve', true), $descriptor->getId());
        static::assertEquals([], $descriptor->getTransports());

        $response = $publicKeyCredential->getResponse();
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);
        static::assertEquals(AttestationStatement::TYPE_SELF, $response->getAttestationObject()->getAttStmt()->getType());
        static::assertInstanceOf(EmptyTrustPath::class, $response->getAttestationObject()->getAttStmt()->getTrustPath());

        $uri = $this->prophesize(UriInterface::class);
        $uri->getHost()->willReturn('spomky-webauthn.herokuapp.com');
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getUri()->willReturn($uri->reveal());

        self::$kernel->getContainer()->get(AuthenticatorAttestationResponseValidator::class)->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request->reveal()
        );
    }
}
