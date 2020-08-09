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

namespace Webauthn\Tests\Functional;

use Base64Url\Base64Url;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Webauthn\AttestedCredentialData;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorData;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSourceRepository;

/**
 * @group functional
 * @group Fido2
 *
 * @internal
 */
class AttestationTest extends AbstractTestCase
{
    /**
     * @test
     */
    public function anAttestationSignedWithEcDSA521ShouldBeVerified(): void
    {
        $options = '{"rp":{"name":"Webauthn Demo","id":"webauthn.spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-46},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39}],"challenge":"MJr5sD0WitVwZM0eoSO6kWhyseT67vc3oQdk_k1VdZQ","attestation":"direct","user":{"name":"zOEOkAZGg3ZrD8l_TFwD","id":"ZDYzNGZlZGQtMGZiNi00ZDY3LWI5OGEtNDk2OWY2ZTMwNTY1","displayName":"Shenika Olin"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":60000}';
        $response = '{"id":"R4fAVj9osgVVZL7yHftPeVOmjom3xw4ZLK7Dt_8mzOM","rawId":"R4fAVj9osgVVZL7yHftPeVOmjom3xw4ZLK7Dt_8mzOM","response":{"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzgjY3NpZ1iLMIGIAkIA-KkXe-BmfxZgJNet2JPOZ6-fjPQskjnqOYWf7LW2iMFDbbZ3_oU18m0IGVksCPOaSsDs6MC14CQSqcQpvo0YxHMCQgFKm882cBfrPs4zM7piS3bM3yG6W4OrS9bbIj34e7b9JNH0Ee-w0cAeUaxQNyyedC4y4fSqvUjDT0f0Mj-iE0-pa2hhdXRoRGF0YVjplgTqgoJOmKStoUtEYtDXOo7EaRMNqRsZMHRZIp90o1lBAAAAlSOIq42JFUFGk7rUPmcdJTgAIEeHwFY_aLIFVWS-8h37T3lTpo6Jt8cOGSyuw7f_JszjpQECAzgjIAMhWEIA6Q6fXXQzt2RH6cq4eKJpfFU4nhmCWH2DKAa33T-uGStxA0zaA3goYphgRW6PkgyETh-Q4I3-NJ6KCx-5QV39v50iWEIAA9xyNnqltQaG2UuiLtuSNM59PLv3skYKKmnAvUDT7J6YwPwVyzOWKOyIfgQc9oPO9dRQ21Da498iOhx5qA5gbRo","clientDataJSON":"eyJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLnNwb21reS1sYWJzLmNvbSIsImNoYWxsZW5nZSI6Ik1KcjVzRDBXaXRWd1pNMGVvU082a1doeXNlVDY3dmMzb1Fka19rMVZkWlEiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"},"type":"public-key"}';

        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::createFromString($options);
        $publicKeyCredential = $this->getPublicKeyCredentialLoader()->load($response);

        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $publicKeyCredential->getResponse());

        $credentialRepository = $this->prophesize(PublicKeyCredentialSourceRepository::class);
        $credentialRepository->findOneByCredentialId(hex2bin('4787c0563f68b2055564bef21dfb4f7953a68e89b7c70e192caec3b7ff26cce3'))->willReturn(null);

        $uri = $this->prophesize(UriInterface::class);
        $uri->getHost()->willReturn('webauthn.spomky-labs.com');
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getUri()->willReturn($uri->reveal());

        $this->getAuthenticatorAttestationResponseValidator($credentialRepository->reveal())->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request->reveal()
        );

        $publicKeyCredentialDescriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor(['usb']);

        static::assertEquals(hex2bin('4787c0563f68b2055564bef21dfb4f7953a68e89b7c70e192caec3b7ff26cce3'), Base64Url::decode($publicKeyCredential->getId()));
        static::assertEquals(hex2bin('4787c0563f68b2055564bef21dfb4f7953a68e89b7c70e192caec3b7ff26cce3'), $publicKeyCredentialDescriptor->getId());
        static::assertEquals(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $publicKeyCredentialDescriptor->getType());
        static::assertEquals(['usb'], $publicKeyCredentialDescriptor->getTransports());

        /** @var AuthenticatorData $authenticatorData */
        $authenticatorData = $publicKeyCredential->getResponse()->getAttestationObject()->getAuthData();

        static::assertEquals(hex2bin('9604ea82824e98a4ada14b4462d0d73a8ec469130da91b19307459229f74a359'), $authenticatorData->getRpIdHash());
        static::assertTrue($authenticatorData->isUserPresent());
        static::assertFalse($authenticatorData->isUserVerified());
        static::assertTrue($authenticatorData->hasAttestedCredentialData());
        static::assertEquals(0, $authenticatorData->getReservedForFutureUse1());
        static::assertEquals(0, $authenticatorData->getReservedForFutureUse2());
        static::assertEquals(149, $authenticatorData->getSignCount());
        static::assertInstanceOf(AttestedCredentialData::class, $authenticatorData->getAttestedCredentialData());
        static::assertFalse($authenticatorData->hasExtensions());
    }

    /**
     * @test
     */
    public function anAttestationWithTokenBindingCanBeVerified(): void
    {
        $options = '{"rp":{"name":"Webauthn Demo","id":"webauthn.spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-46},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39}],"challenge":"b7WOS1hwTuQB1bjiIiXxpAvh8iyl2n8Z3IsicghwIiU","attestation":"direct","user":{"name":"ZpflXdhXVT0tCkJcW0uy","id":"MDY5OTUwNjYtMWRiMy00MTRkLWFmNzctZTBhZjcyNzE1ZTA0","displayName":"Commander Shepard"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":60000}';
        $response = '{"id":"HA7JwKRYhJthdvuwfPt6EzS_QKSj2Su6nJZMtP5qtYE","rawId":"HA7JwKRYhJthdvuwfPt6EzS_QKSj2Su6nJZMtP5qtYE","response":{"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhALs3jP30zEjr4q1hrpRaUTU7u1n8fUAD4uzBeKEX9UjBAiEAkd6hOCt_ePp471AYQOE-ww0NXtkgZzRX24TDB517NcFjeDVjgVkERTCCBEEwggIpoAMCAQICAQEwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA1MjMxNDM5NDNaFw0yODA1MjAxNDM5NDNaMIHCMSMwIQYDVQQDDBpGSURPMiBCQVRDSCBLRVkgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARPOl5eq2wfvK6X9t9kSZZ2LHvvcgBAKnbG8jD2VW8XqpmbWX_Ev1CKr46e8M0BP1q5vSeRS_CAQ3jLzLEbibVGoywwKjAJBgNVHRMEAjAAMB0GA1UdDgQWBBRWTffA-MZVtqEfbE0Z879B4v0BeTANBgkqhkiG9w0BAQsFAAOCAgEAh92gn_ggiQXRLUHOCaTp1HpcBhsOw8ZwTKJBxwYK8ycQ5_QRXBcMRi8axVexH2HoUDTg_u-DkvH2UYGYjX_RAxgGIh4dPgrKXwVndtMwiI5QnQwXMocKtzyyeuSQv6INwk_QCuJL5LOAyPtNUWMTb_UvCcdYWjtZYFOeYQSK9T_6dtWSp6XAhIT4wf3CBaxyai-YiRn3nfi154vUrqtuDh56eODK7-Iezg9npbucln3XxW_kRhtk2FERSBmBoo7IotPd8NGTATnwUvt16vw6x3mW2a6zZGOOeYCQmeXlfNza7fSff1BdFWR5f4cJ0gFAv297Tf5dGZQvZD3DcyQ9OJeJ3RQQ9inX0Nhxk1-6cm1i2e8h9gTN7otjqYmnGjs3ezhPdax2AdrmckO43YNuchfTPECPTRzP4rQo3QbwGLeEAk_HV-oJmYiBkdhf2F2QLMm7SdeqZ1Jjg1W1vNJT288vj1EGF-_aKXg_bujAaK86_YNPBJaW9Rdw4EnfFUi5bEdkD5ZSpeAHCQzCDn2RzkBjs2rTFe4qRFUWtC-RZ4wFqRx70jXLIw-ArpeetpjtzJSNqQsqPlEvpyMxuV2ZjnruA2_ysP3RDzqNs7R8JVNKiie0RAbG7et43ULZcC7oix8JKYsJ6wDmX8Gyy7vWM-LS9XiZUH37sEvwKJbM-xxoYXV0aERhdGFYpJYE6oKCTpikraFLRGLQ1zqOxGkTDakbGTB0WSKfdKNZQQAAAFDissHnR4BCiKI9I9vbyKrsACAcDsnApFiEm2F2-7B8-3oTNL9ApKPZK7qclky0_mq1gaUBAgMmIAEhWCDevGyOQ4AmJvC7Eod70l-MYxt52gdr6D1ZbFpA018n7SJYIP8FQlMVURbJUfOUPalt30CPSgsCj6roSCbDWllEbbBR","clientDataJSON":"eyJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLnNwb21reS1sYWJzLmNvbSIsImNoYWxsZW5nZSI6ImI3V09TMWh3VHVRQjFiamlJaVh4cEF2aDhpeWwybjhaM0lzaWNnaHdJaVUiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"},"type":"public-key"}';

        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::createFromString($options);
        $publicKeyCredential = $this->getPublicKeyCredentialLoader()->load($response);

        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $publicKeyCredential->getResponse());

        $credentialRepository = $this->prophesize(PublicKeyCredentialSourceRepository::class);
        $credentialRepository->findOneByCredentialId(hex2bin('1c0ec9c0a458849b6176fbb07cfb7a1334bf40a4a3d92bba9c964cb4fe6ab581'))->willReturn(null);

        $uri = $this->prophesize(UriInterface::class);
        $uri->getHost()->willReturn('webauthn.spomky-labs.com');
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getUri()->willReturn($uri->reveal());

        $this->getAuthenticatorAttestationResponseValidator($credentialRepository->reveal())->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request->reveal()
        );

        static::fail('This test should fail');
    }

    /**
     * @test
     */
    public function anAttestationWithTokenBindingCanBeVerified1(): void
    {
        $options = '{"rp":{"name":"Webauthn Demo","id":"webauthn.spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-46},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39}],"challenge":"xiPXT8S7ISnukQmXCQfVzxsbCMdyXKuLZannT5_gYLk","attestation":"direct","user":{"name":"XeqoEeTqMuCXfUQTZZJa","id":"ZDg2M2QyODEtZjdjYS00NWNhLWFhYTktYmY3ZTEyODQ3YzRj","displayName":"Latosha Sabatini"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":60000}';
        $response = '{"id":"VKlX8_PlrBwB-nYsH7Z3gdy8Q9eZkT9B0OGmQ1NV60U","rawId":"VKlX8_PlrBwB-nYsH7Z3gdy8Q9eZkT9B0OGmQ1NV60U","response":{"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAOjljLVNh1sxJdlsBRdjlo2ay9QXv8qy8hkDfEv8iGb3AiEAtMtlkuLCJG6Xyif5FbP9f1pFWfwIV6kHuQCkQX8TrnBjeDVjgVkERTCCBEEwggIpoAMCAQICAQEwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA1MjMxNDM5NDNaFw0yODA1MjAxNDM5NDNaMIHCMSMwIQYDVQQDDBpGSURPMiBCQVRDSCBLRVkgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARPOl5eq2wfvK6X9t9kSZZ2LHvvcgBAKnbG8jD2VW8XqpmbWX_Ev1CKr46e8M0BP1q5vSeRS_CAQ3jLzLEbibVGoywwKjAJBgNVHRMEAjAAMB0GA1UdDgQWBBRWTffA-MZVtqEfbE0Z879B4v0BeTANBgkqhkiG9w0BAQsFAAOCAgEAh92gn_ggiQXRLUHOCaTp1HpcBhsOw8ZwTKJBxwYK8ycQ5_QRXBcMRi8axVexH2HoUDTg_u-DkvH2UYGYjX_RAxgGIh4dPgrKXwVndtMwiI5QnQwXMocKtzyyeuSQv6INwk_QCuJL5LOAyPtNUWMTb_UvCcdYWjtZYFOeYQSK9T_6dtWSp6XAhIT4wf3CBaxyai-YiRn3nfi154vUrqtuDh56eODK7-Iezg9npbucln3XxW_kRhtk2FERSBmBoo7IotPd8NGTATnwUvt16vw6x3mW2a6zZGOOeYCQmeXlfNza7fSff1BdFWR5f4cJ0gFAv297Tf5dGZQvZD3DcyQ9OJeJ3RQQ9inX0Nhxk1-6cm1i2e8h9gTN7otjqYmnGjs3ezhPdax2AdrmckO43YNuchfTPECPTRzP4rQo3QbwGLeEAk_HV-oJmYiBkdhf2F2QLMm7SdeqZ1Jjg1W1vNJT288vj1EGF-_aKXg_bujAaK86_YNPBJaW9Rdw4EnfFUi5bEdkD5ZSpeAHCQzCDn2RzkBjs2rTFe4qRFUWtC-RZ4wFqRx70jXLIw-ArpeetpjtzJSNqQsqPlEvpyMxuV2ZjnruA2_ysP3RDzqNs7R8JVNKiie0RAbG7et43ULZcC7oix8JKYsJ6wDmX8Gyy7vWM-LS9XiZUH37sEvwKJbM-xxoYXV0aERhdGFYpJYE6oKCTpikraFLRGLQ1zqOxGkTDakbGTB0WSKfdKNZQQAAAFMBsvkSwB9MiIeWs6KC5AU6ACBUqVfz8-WsHAH6diwftneB3LxD15mRP0HQ4aZDU1XrRaUBAgMmIAEhWCDGTT_18aGsfGchCnWRLkqKiH7vqYKSpkTZYMtj44ZMtiJYIDFz_ybOb1ojAlFIkh2P_q-yp5G9gaJRRHeGS2ln3Epw","clientDataJSON":"eyJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLnNwb21reS1sYWJzLmNvbSIsImNoYWxsZW5nZSI6InhpUFhUOFM3SVNudWtRbVhDUWZWenhzYkNNZHlYS3VMWmFublQ1X2dZTGsiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"},"type":"public-key"}';

        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::createFromString($options);
        $publicKeyCredential = $this->getPublicKeyCredentialLoader()->load($response);

        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $publicKeyCredential->getResponse());

        $credentialRepository = $this->prophesize(PublicKeyCredentialSourceRepository::class);
        $credentialRepository->findOneByCredentialId(hex2bin('1c0ec9c0a458849b6176fbb07cfb7a1334bf40a4a3d92bba9c964cb4fe6ab581'))->willReturn(null);

        $uri = $this->prophesize(UriInterface::class);
        $uri->getHost()->willReturn('webauthn.spomky-labs.com');
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getUri()->willReturn($uri->reveal());

        $this->getAuthenticatorAttestationResponseValidator($credentialRepository->reveal())->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request->reveal()
        );

        static::fail('This test should fail');
    }
}
