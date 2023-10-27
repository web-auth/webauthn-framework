<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use DateTimeImmutable;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AttestedCredentialData;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorData;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\AbstractTestCase;

/**
 * @internal
 */
final class AppleAttestationStatementTest extends AbstractTestCase
{
    #[Test]
    public function anAppleAttestationCanBeVerified(): void
    {
        $this->clock->set((new DateTimeImmutable())->setTimestamp(1_600_000_000));
        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('My Application'),
            PublicKeyCredentialUserEntity::create(
                'test@foo.com',
                random_bytes(64),
                'Test PublicKeyCredentialUserEntity'
            ),
            base64_decode('h5xSyIRMx2IQPr1mQk6GD98XSQOBHgMHVpJIkMV9Nkc=', true),
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT
        );
        $publicKeyCredential = $this->getPublicKeyCredentialLoader()
            ->load('{
            "id": "J4lAqPXhefDrUD7oh5LQMbBH5TE",
            "rawId": "J4lAqPXhefDrUD7oh5LQMbBH5TE",
            "response": {
                "attestationObject": "o2NmbXRlYXBwbGVnYXR0U3RtdKJjYWxnJmN4NWOCWQJHMIICQzCCAcmgAwIBAgIGAXSFZw11MAoGCCqGSM49BAMCMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAwOTEzMDI0OTE3WhcNMjAwOTE0MDI1OTE3WjCBkTFJMEcGA1UEAwxAMzI3ZWI1ODhmMTU3ZDZiYjY0NTRmOTdmNWU1NmM4NmY0NGI1MDdjODgxOGZmMjMwYmQwZjYyNWJkYjY1YmNiNjEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARiAlQ11YPbcpjmwM93iOefyu00h8-4BALNKnBDB5I9n17wD5wNqP0hYua340eB75Z1L_V6I7R4qraq7763zj9mo1UwUzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB_wQEAwIE8DAzBgkqhkiG92NkCAIEJjAkoSIEIPuwR1EQvcCtYCRahnJWisqz6YYLEAXH16p0WXbLfY6tMAoGCCqGSM49BAMCA2gAMGUCMDpEvt_ifVr8uu1rnLykezfrHBXwLL-D6DO73l_sX_DLRwXDmqTiPSx0WHiB554m5AIxAIAXIId3WdSC2B2zYFm4ZsJP_jAgjTL1GguZ-Ae78AN2AcjKblEabOdkbKr0aL_M9FkCODCCAjQwggG6oAMCAQICEFYlU5XHp_tA6-Io2CYIU7YwCgYIKoZIzj0EAwMwSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODM4MDFaFw0zMDAzMTMwMDAwMDBaMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASDLocvJhSRgQIlufX81rtjeLX1Xz_LBFvHNZk0df1UkETfm_4ZIRdlxpod2gULONRQg0AaQ0-yTREtVsPhz7_LmJH-wGlggb75bLx3yI3dr0alruHdUVta-quTvpwLJpGjZjBkMBIGA1UdEwEB_wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUJtdk2cV4wlpn0afeaxLQG2PxxtcwHQYDVR0OBBYEFOuugsT_oaxbUdTPJGEFAL5jvXeIMA4GA1UdDwEB_wQEAwIBBjAKBggqhkjOPQQDAwNoADBlAjEA3YsaNIGl-tnbtOdle4QeFEwnt1uHakGGwrFHV1Azcifv5VRFfvZIlQxjLlxIPnDBAjAsimBE3CAfz-Wbw00pMMFIeFHZYO1qdfHrSsq-OM0luJfQyAW-8Mf3iwelccboDgdoYXV0aERhdGFYmD3cRxDpwIiyKduonVYyILs59yKa_0ZbCmVrGvuaivigRQAAAAAAAAAAAAAAAAAAAAAAAAAAABQniUCo9eF58OtQPuiHktAxsEflMaUBAgMmIAEhWCBiAlQ11YPbcpjmwM93iOefyu00h8-4BALNKnBDB5I9nyJYIF7wD5wNqP0hYua340eB75Z1L_V6I7R4qraq7763zj9m",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiaDV4U3lJUk14MklRUHIxbVFrNkdEOThYU1FPQkhnTUhWcEpJa01WOU5rYyIsIm9yaWdpbiI6Imh0dHBzOi8vZGV2LmRvbnRuZWVkYS5wdyJ9"
            },
            "type": "public-key"
        }');
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $publicKeyCredential->response);
        $this->getAuthenticatorAttestationResponseValidator()
            ->check($publicKeyCredential->response, $publicKeyCredentialCreationOptions, 'dev.dontneeda.pw');
        $publicKeyCredentialDescriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor(['usb']);
        static::assertSame(
            base64_decode('J4lAqPXhefDrUD7oh5LQMbBH5TE', true),
            Base64UrlSafe::decode($publicKeyCredential->id)
        );
        static::assertSame(base64_decode('J4lAqPXhefDrUD7oh5LQMbBH5TE', true), $publicKeyCredentialDescriptor->id);
        static::assertSame(
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $publicKeyCredentialDescriptor->type
        );
        static::assertSame(['usb'], $publicKeyCredentialDescriptor->transports);
        /** @var AuthenticatorData $authenticatorData */
        $authenticatorData = $publicKeyCredential->response
            ->attestationObject
            ->getAuthData();
        /** @var AttestationStatement $attestationStatement */
        $attestationStatement = $publicKeyCredential->response
            ->attestationObject
            ->getAttStmt();
        static::assertSame(AttestationStatement::TYPE_ANONCA, $attestationStatement->type);
        static::assertSame(
            hex2bin('3ddc4710e9c088b229dba89d563220bb39f7229aff465b0a656b1afb9a8af8a0'),
            $authenticatorData->rpIdHash
        );
        static::assertTrue($authenticatorData->isUserPresent());
        static::assertTrue($authenticatorData->isUserVerified());
        static::assertTrue($authenticatorData->hasAttestedCredentialData());
        static::assertSame(0, $authenticatorData->getReservedForFutureUse1());
        static::assertSame(0, $authenticatorData->getReservedForFutureUse2());
        static::assertSame(0, $authenticatorData->signCount);
        static::assertInstanceOf(AttestedCredentialData::class, $authenticatorData->attestedCredentialData);
        static::assertFalse($authenticatorData->hasExtensions());
        $this->clock->set(new DateTimeImmutable());
    }
}
