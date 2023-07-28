<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Attestation;

use Cose\Algorithms;
use PHPUnit\Framework\Attributes\Test;
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
use Webauthn\Tests\MockedRequestTrait;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * @internal
 */
final class PackedAttestationStatementTest extends KernelTestCase
{
    use MockedRequestTrait;

    #[Test]
    public function aPackedAttestationWithSelfStatementCanBeVerified(): void
    {
        self::bootKernel();
        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('My Application'),
            PublicKeyCredentialUserEntity::create(
                'test@foo.com',
                random_bytes(64),
                'Test PublicKeyCredentialUserEntity'
            ),
            base64_decode('oFUGhUevQHX7J6o4OFau5PbncCATaHwjHDLLzCTpiyw=', true),
            [new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_ES256)]
        )->setAttestation(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT);
        $publicKeyCredential = self::$kernel->getContainer()->get(PublicKeyCredentialLoader::class)->load(
            '{"id":"AFkzwaxVuCUz4qFPaNAgnYgoZKKTtvGIAaIASAbnlHGy8UktdI_jN0CetpIkiw9--R0AF9a6OJnHD-G4aIWur-Pxj-sI9xDE-AVeQKve","type":"public-key","rawId":"AFkzwaxVuCUz4qFPaNAgnYgoZKKTtvGIAaIASAbnlHGy8UktdI/jN0CetpIkiw9++R0AF9a6OJnHD+G4aIWur+Pxj+sI9xDE+AVeQKve","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJvRlVHaFVldlFIWDdKNm80T0ZhdTVQYm5jQ0FUYUh3akhETEx6Q1RwaXl3Iiwib3JpZ2luIjoiaHR0cHM6Ly9zcG9ta3ktd2ViYXV0aG4uaGVyb2t1YXBwLmNvbSIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgAMCQZYRl2cA+ab2MB3OGBCbq3j62rSubwhaCVSHJvKMCIQD0mMLs/5jjwd0KxYzb9/iM15T1gJ3L1Uv5BnMtQtVYBmhhdXRoRGF0YVjStIXbbgSILsWHHbR0Fjkl96X4ROZYLvVtOopBWCQoAqpFXE8bBwAAAAAAAAAAAAAAAAAAAAAATgBZM8GsVbglM+KhT2jQIJ2IKGSik7bxiAGiAEgG55RxsvFJLXSP4zdAnraSJIsPfvkdABfWujiZxw/huGiFrq/j8Y/rCPcQxPgFXkCr3qUBAgMmIAEhWCBOSwRVQxXPb76nvmQ2HQ8i5Bin8M4zfZCqIlKXrcxxmyJYIOFCAZ9+rRhklvn1nk2TahaCvpH96emEuKoGxpEObvQg"}}'
        );
        $descriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor();
        static::assertSame(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $descriptor->type);
        static::assertSame(
            base64_decode(
                'AFkzwaxVuCUz4qFPaNAgnYgoZKKTtvGIAaIASAbnlHGy8UktdI/jN0CetpIkiw9++R0AF9a6OJnHD+G4aIWur+Pxj+sI9xDE+AVeQKve',
                true
            ),
            $descriptor->id
        );
        static::assertSame([], $descriptor->transports);
        $response = $publicKeyCredential->response;
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);
        static::assertSame(AttestationStatement::TYPE_SELF, $response->attestationObject->attStmt->type);
        static::assertInstanceOf(EmptyTrustPath::class, $response->attestationObject ->attStmt ->trustPath);
        self::$kernel->getContainer()->get(AuthenticatorAttestationResponseValidator::class)->check(
            $publicKeyCredential->response,
            $publicKeyCredentialCreationOptions,
            'spomky-webauthn.herokuapp.com'
        );
    }
}
