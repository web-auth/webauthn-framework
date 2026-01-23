<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\Counter\ThrowExceptionIfInvalid;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\Tests\AbstractTestCase;
use Webauthn\TrustPath\TrustPath;

/**
 * @internal
 */
final class ValidatorCompatibilityTest extends AbstractTestCase
{
    #[Test]
    public function assertionValidatorWorksWithCredentialRecord(): void
    {
        $publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions::create(
            base64_decode('G0JbLLndef3a0Iy3S2sSQA8uO4SO/ze6FZMAuPI6+xI=', true),
            rpId: 'localhost',
            allowCredentials: [
                PublicKeyCredentialDescriptor::create(
                    PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                    Base64UrlSafe::decode(
                        'eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
                        true
                    )
                ),
            ],
            userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            timeout: 60000,
        );

        $publicKeyCredential = $this->getSerializer()
            ->deserialize(
                '{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"public-key","rawId":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAew","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ","signature":"MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=","userHandle":null}}',
                PublicKeyCredential::class,
                'json'
            );

        static::assertInstanceOf(AuthenticatorAssertionResponse::class, $publicKeyCredential->response);

        // Create a CredentialRecord (not PublicKeyCredentialSource)
        $credentialRecord = CredentialRecord::create(
            base64_decode(
                'eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==',
                true
            ),
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            $this->createMock(TrustPath::class),
            Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            base64_decode(
                'pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=',
                true
            ),
            'foo',
            100
        );

        $validator = $this->getAuthenticatorAssertionResponseValidator();

        $updatedCredentialRecord = $validator->check(
            $credentialRecord,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            'localhost',
            'foo'
        );

        // Validator should return a CredentialRecord
        static::assertInstanceOf(CredentialRecord::class, $updatedCredentialRecord);
        static::assertSame(123, $updatedCredentialRecord->counter);
    }

    #[Test]
    public function assertionValidatorWorksWithPublicKeyCredentialSource(): void
    {
        $publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions::create(
            base64_decode('G0JbLLndef3a0Iy3S2sSQA8uO4SO/ze6FZMAuPI6+xI=', true),
            rpId: 'localhost',
            allowCredentials: [
                PublicKeyCredentialDescriptor::create(
                    PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                    Base64UrlSafe::decode(
                        'eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
                        true
                    )
                ),
            ],
            userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            timeout: 60000,
        );

        $publicKeyCredential = $this->getSerializer()
            ->deserialize(
                '{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"public-key","rawId":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAew","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ","signature":"MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=","userHandle":null}}',
                PublicKeyCredential::class,
                'json'
            );

        static::assertInstanceOf(AuthenticatorAssertionResponse::class, $publicKeyCredential->response);

        // Create a PublicKeyCredentialSource (deprecated but should still work)
        $publicKeyCredentialSource = new PublicKeyCredentialSource(
            base64_decode(
                'eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==',
                true
            ),
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            $this->createMock(TrustPath::class),
            Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            base64_decode(
                'pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=',
                true
            ),
            'foo',
            100
        );

        $validator = $this->getAuthenticatorAssertionResponseValidator();

        $updatedPkcs = $validator->check(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            'localhost',
            'foo'
        );

        // Validator returns CredentialRecord; PKCS extends CR so it's both
        static::assertInstanceOf(PublicKeyCredentialSource::class, $updatedPkcs);
        static::assertInstanceOf(CredentialRecord::class, $updatedPkcs);
        static::assertSame(123, $updatedPkcs->counter);
    }

    #[Test]
    public function ceremonyStepsWorkWithBothTypes(): void
    {
        // Test that ceremony steps can process both CredentialRecord and PublicKeyCredentialSource
        $credentialRecord = CredentialRecord::create(
            'test-id',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            $this->createMock(TrustPath::class),
            Uuid::v4(),
            'public-key',
            'user-handle',
            10
        );

        $pkcs = new PublicKeyCredentialSource(
            'test-id-2',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            $this->createMock(TrustPath::class),
            Uuid::v4(),
            'public-key-2',
            'user-handle-2',
            20
        );

        // Both types should work with ceremony steps
        static::assertInstanceOf(CredentialRecord::class, $credentialRecord);
        static::assertInstanceOf(PublicKeyCredentialSource::class, $pkcs);
        // PKCS extends CredentialRecord
        static::assertInstanceOf(CredentialRecord::class, $pkcs);
        static::assertNotInstanceOf(PublicKeyCredentialSource::class, $credentialRecord);
    }

    #[Test]
    public function counterCheckerWorksWithBothTypes(): void
    {
        $counterChecker = new ThrowExceptionIfInvalid();

        $credentialRecord = CredentialRecord::create(
            'test-id',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            $this->createMock(TrustPath::class),
            Uuid::v4(),
            'public-key',
            'user-handle',
            10
        );

        $pkcs = new PublicKeyCredentialSource(
            'test-id-2',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            $this->createMock(TrustPath::class),
            Uuid::v4(),
            'public-key-2',
            'user-handle-2',
            20
        );

        // Should work with CredentialRecord
        $counterChecker->check($credentialRecord, 11);
        static::assertTrue(true); // No exception means success

        // Should work with PublicKeyCredentialSource
        $counterChecker->check($pkcs, 21);
        static::assertTrue(true); // No exception means success
    }
}
