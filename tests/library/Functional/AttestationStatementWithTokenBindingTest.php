<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use Cose\Algorithms;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use Webauthn\AttestedCredentialData;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorData;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\AbstractTestCase;

/**
 * @internal
 */
final class AttestationStatementWithTokenBindingTest extends AbstractTestCase
{
    #[Test]
    public function anAttestationWithTokenBindingCanBeVerified(): void
    {
        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('My Application'),
            PublicKeyCredentialUserEntity::create(
                'test@foo.com',
                random_bytes(64),
                'Test PublicKeyCredentialUserEntity'
            ),
            base64_decode(
                'SkehMoAkGv+cqmuiEqpOgGhswj5oDa9kIPxgG1IihzkxPe4LNfP8bUyFiNn/MXBlqiOY6IpHFZl1XfIM07kRZw==',
                true
            ),
            [PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_ES256)],
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
        );
        $publicKeyCredential = $this->getPublicKeyCredentialLoader()
            ->load(
                '{"id":"-uZVS9-4JgjAYI49YhdzTgHmbn638-ZNSvC0UtHkWTVS-CtTjnaSbqtzdzijByOAvEAsh-TaQJAr43FRj-dYag","type":"public-key","rawId":"+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYag==","response":{"clientDataJSON":"ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5jcmVhdGUiLA0KCSJjaGFsbGVuZ2UiIDogIlNrZWhNb0FrR3YtY3FtdWlFcXBPZ0doc3dqNW9EYTlrSVB4Z0cxSWloemt4UGU0TE5mUDhiVXlGaU5uX01YQmxxaU9ZNklwSEZabDFYZklNMDdrUlp3IiwNCgkib3JpZ2luIiA6ICJodHRwczovL3dlYmF1dGhuLm1vcnNlbGxpLmZyIiwNCgkidG9rZW5CaW5kaW5nIiA6IA0KCXsNCgkJInN0YXR1cyIgOiAic3VwcG9ydGVkIg0KCX0NCn0","attestationObject":"o2NmbXRmcGFja2VkaGF1dGhEYXRhWMTK1G7bmWFTI+ZiJL3+irxdWcwtIGMCnePpskIEiQlDtkUAAACS+KAR84wKTRWABhcRH57cfQBA+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYaqUBAgMmIAEhWCBghVX3//iILN98CBMBKcKrotdlzBdLaH/Hg88GTQV/HiJYIHJsHBPRfVuaLrsZcyiWxCSMZlJZkR7wZMg4a6oZ+zacZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgF/4vvqanyO+5+IHsw8GbSWh+qLHbejybS9K7mpIhR/ACIQCMImx8JpQjbCXrXxwJ1uUnwQcTXBVU3+luI56lJ+S9kGN4NWOBWQLCMIICvjCCAaagAwIBAgIEdIb9wjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk1NTAwMzg0MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJVd8633JH0xde/9nMTzGk6HjrrhgQlWYVD7OIsuX2Unv1dAmqWBpQ0KxS8YRFwKE1SKE1PIpOWacE5SO8BN6+2jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER+e3H0wDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMVxIgOaaUn44Zom9af0KqG9J655OhUVBVW+q0As6AIod3AH5bHb2aDYakeIyyBCnnGMHTJtuekbrHbXYXERIn4aKdkPSKlyGLsA/A+WEi+OAfXrNVfjhrh7iE6xzq0sg4/vVJoywe4eAJx0fS+Dl3axzTTpYl71Nc7p/NX6iCMmdik0pAuYJegBcTckE3AoYEg4K99AM/JaaKIblsbFh8+3LxnemeNf7UwOczaGGvjS6UzGVI0Odf9lKcPIwYhuTxM5CaNMXTZQ7xq4/yTfC3kPWtE4hFT34UJJflZBiLrxG4OsYxkHw/n5vKgmpspB3GfYuYTWhkDKiE8CYtyg87g=="}}'
            );
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $publicKeyCredential->response);
        $this->getAuthenticatorAttestationResponseValidator()
            ->check($publicKeyCredential->response, $publicKeyCredentialCreationOptions, 'webauthn.morselli.fr');
        $publicKeyCredentialDescriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor(['usb']);
        static::assertSame(
            base64_decode(
                '+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYag==',
                true
            ),
            Base64UrlSafe::decode($publicKeyCredential->id)
        );
        static::assertSame(
            base64_decode(
                '+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYag==',
                true
            ),
            $publicKeyCredentialDescriptor->id
        );
        static::assertSame(
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $publicKeyCredentialDescriptor->type
        );
        static::assertSame(['usb'], $publicKeyCredentialDescriptor->transports);
        /** @var AuthenticatorData $authenticatorData */
        $authenticatorData = $publicKeyCredential->response
            ->attestationObject
            ->authData;
        static::assertSame(
            hex2bin('cad46edb99615323e66224bdfe8abc5d59cc2d2063029de3e9b24204890943b6'),
            $authenticatorData->rpIdHash
        );
        static::assertTrue($authenticatorData->isUserPresent());
        static::assertTrue($authenticatorData->isUserVerified());
        static::assertTrue($authenticatorData->hasAttestedCredentialData());
        static::assertSame(0, $authenticatorData->getReservedForFutureUse1());
        static::assertSame(0, $authenticatorData->getReservedForFutureUse2());
        static::assertSame(146, $authenticatorData->signCount);
        static::assertInstanceOf(AttestedCredentialData::class, $authenticatorData->attestedCredentialData);
        static::assertFalse($authenticatorData->hasExtensions());
    }
}
