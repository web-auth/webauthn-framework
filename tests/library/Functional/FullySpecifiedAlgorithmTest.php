<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use Cose\Algorithms;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\AbstractTestCase;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * RFC 9864 introduced fully-specified COSE algorithm identifiers. Webauthn Level 3 integrated them and states that,
 * within Webauthn, -9 (ESP256) designates the same algorithm as -7 (ES256). They are NOT RECOMMENDED in
 * "pubKeyCredParams", but a credential public key using one of them must be accepted and verified.
 *
 * @internal
 *
 * @see https://w3c.github.io/webauthn/#sctn-alg-identifier
 * @see https://www.rfc-editor.org/rfc/rfc9864.html
 */
final class FullySpecifiedAlgorithmTest extends AbstractTestCase
{
    private const CREATION_CHALLENGE = 'ibNMP4WThXFwp8eSNv3wa0+EB3FQiPaITUnMeDmxTrM=';

    private const CREATION_RESPONSE = '{"id":"wjx--Lp0oijWh8D5fweRbEOjY3XbvP747BxwtljjHNM","type":"public-key","rawId":"wjx--Lp0oijWh8D5fweRbEOjY3XbvP747BxwtljjHNM","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiaWJOTVA0V1RoWEZ3cDhlU052M3dhMC1FQjNGUWlQYUlUVW5NZURteFRyTSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0IiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAIMI8fvi6dKIo1ofA-X8HkWxDo2N127z--OwccLZY4xzTpQECAyggASFYILhXOF5y-BqmyXZF9nkCs-72ZumzzUfFiVNQMKRzIvDJIlggP7fRyu5MfyBivcILh7hKaPE4cyHdgnQlilEClqa9RUA"}}';

    private const REQUEST_CHALLENGE = 'vDJjiC/dEsSOnQHze4wXcbdv9U+v4zz7+zkjRvgsWzU=';

    private const REQUEST_RESPONSE = '{"id":"wjx--Lp0oijWh8D5fweRbEOjY3XbvP747BxwtljjHNM","type":"public-key","rawId":"wjx--Lp0oijWh8D5fweRbEOjY3XbvP747BxwtljjHNM","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAew","clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidkRKamlDX2RFc1NPblFIemU0d1hjYmR2OVUtdjR6ejctemtqUnZnc1d6VSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0IiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ","signature":"MEQCICW9HmaH72j59Wy8lWzgQAXoEUKdEWH9SR_6hAAvouNZAiADsxl31bJQdUiOAcxqJ8GC70zX8nB-ZY9k37c7eYOgSA","userHandle":null}}';

    private const CREDENTIAL_ID = 'wjx++Lp0oijWh8D5fweRbEOjY3XbvP747BxwtljjHNM=';

    private const CREDENTIAL_PUBLIC_KEY = 'pQECAyggASFYILhXOF5y+BqmyXZF9nkCs+72ZumzzUfFiVNQMKRzIvDJIlggP7fRyu5MfyBivcILh7hKaPE4cyHdgnQlilEClqa9RUA=';

    #[Test]
    public function anEsp256CredentialCanBeRegistered(): void
    {
        // Given
        $publicKeyCredentialCreationOptions = $this->createCreationOptions([
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_ESP256),
        ]);
        $publicKeyCredential = $this->getSerializer()
            ->deserialize(self::CREATION_RESPONSE, PublicKeyCredential::class, 'json');
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $publicKeyCredential->response);

        // When
        $credentialRecord = $this->getAuthenticatorAttestationResponseValidator()
            ->check($publicKeyCredential->response, $publicKeyCredentialCreationOptions, 'localhost');

        // Then
        static::assertSame(
            base64_decode(self::CREDENTIAL_PUBLIC_KEY, true),
            $credentialRecord->credentialPublicKey
        );
    }

    #[Test]
    public function anEsp256CredentialIsAcceptedWhenEs256WasRequested(): void
    {
        // Given
        $publicKeyCredentialCreationOptions = $this->createCreationOptions([
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_ES256),
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_RS256),
        ]);
        $publicKeyCredential = $this->getSerializer()
            ->deserialize(self::CREATION_RESPONSE, PublicKeyCredential::class, 'json');
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $publicKeyCredential->response);

        // When
        $credentialRecord = $this->getAuthenticatorAttestationResponseValidator()
            ->check($publicKeyCredential->response, $publicKeyCredentialCreationOptions, 'localhost');

        // Then
        static::assertSame(
            base64_decode(self::CREDENTIAL_PUBLIC_KEY, true),
            $credentialRecord->credentialPublicKey
        );
    }

    #[Test]
    public function anEsp256CredentialIsRejectedWhenAnotherAlgorithmWasRequested(): void
    {
        // Given
        $publicKeyCredentialCreationOptions = $this->createCreationOptions([
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_RS256),
        ]);
        $publicKeyCredential = $this->getSerializer()
            ->deserialize(self::CREATION_RESPONSE, PublicKeyCredential::class, 'json');
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $publicKeyCredential->response);

        // Then
        $this->expectExceptionMessage('Invalid algorithm. Expected one of -257 but got -9');

        // When
        $this->getAuthenticatorAttestationResponseValidator()
            ->check($publicKeyCredential->response, $publicKeyCredentialCreationOptions, 'localhost');
    }

    #[Test]
    public function anEsp256AssertionCanBeVerified(): void
    {
        // Given
        $credentialId = base64_decode(self::CREDENTIAL_ID, true);
        $publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions::create(
            base64_decode(self::REQUEST_CHALLENGE, true),
            'localhost',
            [
                PublicKeyCredentialDescriptor::create(
                    PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                    $credentialId
                ),
            ]
        );
        $publicKeyCredential = $this->getSerializer()
            ->deserialize(self::REQUEST_RESPONSE, PublicKeyCredential::class, 'json');
        static::assertInstanceOf(AuthenticatorAssertionResponse::class, $publicKeyCredential->response);
        $credentialRecord = CredentialRecord::create(
            $credentialId,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            base64_decode(self::CREDENTIAL_PUBLIC_KEY, true),
            'foo',
            100
        );

        // When
        $credentialRecord = $this->getAuthenticatorAssertionResponseValidator()
            ->check(
                $credentialRecord,
                $publicKeyCredential->response,
                $publicKeyCredentialRequestOptions,
                'localhost',
                'foo'
            );

        // Then
        static::assertSame(123, $credentialRecord->counter);
    }

    /**
     * @param PublicKeyCredentialParameters[] $pubKeyCredParams
     */
    private function createCreationOptions(array $pubKeyCredParams): PublicKeyCredentialCreationOptions
    {
        return PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('My Application', 'localhost'),
            PublicKeyCredentialUserEntity::create('test@foo.com', Base64UrlSafe::decode('Zm9v', true), 'Test User'),
            base64_decode(self::CREATION_CHALLENGE, true),
            $pubKeyCredParams
        );
    }
}
