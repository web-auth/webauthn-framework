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

    /**
     * @test
     */
    public function anAssertionWithACompleteChainCannotBeAccepted(): void
    {
        $options = '{"status":"ok","errorMessage":"","rp":{"name":"Webauthn Demo","id":"webauthn.spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-46},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39}],"challenge":"TZtQJA4AHCTm3xPjFMCWkcTfag4ryFIhpHuBmAXsYgM","attestation":"direct","user":{"name":"HjERUA2aSl9hI3kBLhN_","id":"M2ZiZmMyZWEtNDAwZS00MGNjLTk4ZTYtNDQyOTdiM2FiN2U2","displayName":"Alec Palazzo"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":60000}';
        $response = '{"id":"pxAOzSOfFJsw5tO2xtJ936dABP5-20Hx6qgU7bLJ958","rawId":"pxAOzSOfFJsw5tO2xtJ936dABP5-20Hx6qgU7bLJ958","response":{"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgEGmcxydEITjIg8tvk15UuWwDszy3u-v9JaES_SGSs9ICIQDEb2giJ8hhsmZ79hp1wb8d-9xCp-3pZ8jo-LNvT2-m_WN4NWODWQKSMIICjjCCAjSgAwIBAgIBATAKBggqhkjOPQQDAjCBrzEmMCQGA1UEAwwdRklETzIgSU5URVJNRURJQVRFIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTIzMTQzNzQxWhcNMjgwNTIwMTQzNzQxWjCBwjEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEutlirPGtUi-a-woMkhwX2-s6mZPQpKNmY77E9cvyGvuAZGllHFGRg_R8kQ_MKjRlMrcP68cW2x0OAb1XbilIZKMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUSlTlBtKRRE9tDzNd1v3HRmy5X1QwCgYIKoZIzj0EAwIDSAAwRQIhALlbNrRzfaOsENMNvvXrleUEJ0JaRJV_O-GGodN_J-pFAiBNC6zAOECkfCpP9fpbxphxyp6cpv0coXwM1pGEczcpeFkENTCCBDEwggIZoAMCAQICAQIwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA3MjMxNDI5MDdaFw00NTEyMDgxNDI5MDdaMIGvMSYwJAYDVQQDDB1GSURPMiBJTlRFUk1FRElBVEUgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNxBHd9VbX9Nc4ypdRR6VXH0YwApI9ZvtHtel4cgcFkFDsnOh6lvNFeK1N0ItMJ81eksTUbolFyy0-Zf20tJefOjLzAtMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFGfBGZKQW_VdAMHWIQ6MLXYhkkfAMA0GCSqGSIb3DQEBCwUAA4ICAQALmC6ns1S7Byd2J-_l3CVnoYhI9MRyJB0zGY2j2cT0FEA7Zu1DQN0l2J8DwadBB3b10iCTxTjxa5xjirO69FlorrPoAitTZsBSUmsqeVNm-N2IzeiJNj1ZOIH17J-Yr9mAS_tb0MQVbu-uHfb6mNI0XVXLG4wSmdrVfqzKq00NUb7DRguN2ReLRyK5EnLRD0D3S-YwqADGCdF8KiXlpBSUelkxOIr7w4KnyxKirTlA3f2LLfi7gB4oZRZ64qNgTA2yAqCf6_X4DV1tTDZxZiDnc6Lmb8NAuW35azWGiS7BfEJ6RoG-J4H2e7Xd9he_tKSDC5Y83DIU-VCRakg-Bv15kwTeSdSInYQBLVQTuStpY2DdxA7a_q1jbj7n4WYTK5aKcYKGsezBPSxi2aFAaVZrRsJX18Qsvr1sI7rhGJah6cuyJfXmGaYLv5lsX0PVUePUEdH16KgBlRWicSIMlJke1XFeWZTeNAGGsQ_O0XlGfrvR3Or8Tgcs9_Nuspb4vYXaL5YRYXty2Jw1UEEtdQewUC8Zgyq_sMTTMMZpnsv6NciNIKITYiOLEKExjD9oVjCbHQ3rK5d4kNi7x8JJc4pM9HplGwsJDfy1cVJBHKfVPkWC_F2ztDazGC1VcI3LwUyih_buCMy7mLikC3aV1cQ7HXMjY_42_oYXFjZT8G1cg3kHsE1JSUZ3RENDQTZnQ0NRQ05tMXU1Nm9Sd1hUQU5CZ2txaGtpRzl3MEJBUXNGQURDQm9URVlNQllHQTFVRUF3d1BSa2xFVHpJZ1ZFVlRWQ0JTVDA5VU1URXdMd1lKS29aSWh2Y05BUWtCRmlKamIyNW1iM0p0WVc1alpTMTBiMjlzYzBCbWFXUnZZV3hzYVdGdVkyVXViM0puTVJZd0ZBWURWUVFLREExR1NVUlBJRUZzYkdsaGJtTmxNUXd3Q2dZRFZRUUxEQU5EVjBjeEN6QUpCZ05WQkFZVEFsVlRNUXN3Q1FZRFZRUUlEQUpOV1RFU01CQUdBMVVFQnd3SlYyRnJaV1pwWld4a01CNFhEVEU0TURNeE5qRTBNelV5TjFvWERUUTFNRGd3TVRFME16VXlOMW93Z2FFeEdEQVdCZ05WQkFNTUQwWkpSRTh5SUZSRlUxUWdVazlQVkRFeE1DOEdDU3FHU0liM0RRRUpBUllpWTI5dVptOXliV0Z1WTJVdGRHOXZiSE5BWm1sa2IyRnNiR2xoYm1ObExtOXlaekVXTUJRR0ExVUVDZ3dOUmtsRVR5QkJiR3hwWVc1alpURU1NQW9HQTFVRUN3d0RRMWRITVFzd0NRWURWUVFHRXdKVlV6RUxNQWtHQTFVRUNBd0NUVmt4RWpBUUJnTlZCQWNNQ1ZkaGEyVm1hV1ZzWkRDQ0FpSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnSVBBRENDQWdvQ2dnSUJBTDExVTV5QUlWTE1yTDN4Uzh1OHlzTVNkT2tEZW9UTytSY0F5K3VYWHA2azRTQytqT3kzN2dJQ0V0WUkrTUtRVjFFTWVNTWYzck0xdWVaQU8zaVBGYTBORWRpL29RN25wbkdqQk5JOHdNekQ4RmZOZTZyV3R6a0RhSHBzWlcvLy9Nd1dEcEd5SlIrWHlqY3E2VTR2UzliUzZ6Wjdqc2x3ME9jeng0VXNZZ09zSVVYU1NCYUdPclJieEovSkM1Z25EWUVZdnROTStQRFBjekxOS0F5aGR2QlpXTldIcjdNWjBQNVRlSlFjWHNBb1NoUlgyWThVOGZSTkptN1NlaUZLRFAwTm4vUUt4T1N0N3pHUDR4dDluTWFzRTFxMlpUZGFyMitXMTNDUnozN1JJMFpXcHEvK1lxdW9FYlo3VWo3Tm1CVGNxaGIyNjBubURFUjJGcHd3WXdQU2FyazkySVpiYW1vekI4ZDdPRUkxakpnc3JqSmhLYW4wRW1SYVdWQnBIVDR4WUtkRXU3cjA5UzBKaEt5VSs1MldEbW1WUVRNcFlMcm00WGw3aFJ4eVB5QllrYWxyb3pzR21Qczh2bGhOcTNWc1ZieUJTTVNwRW1VYWVBYTdMTEU5L1ZoMGFnSkxWRkhoMWVoWUtKcHpIbm1tQlhVcXgwRnozYWZtRG0xTlgwc3IzTy82eEl4MVZTVFZpVDNLTnhCWXBWSDFxakhBVEx6dXhjV21tKzc1ZmNKTWlQWVBTTVhWbVJiM1ExbDkxQU00QkJlV2hsUDNGYmM3Z0R5MHIrczdtMHNHUzZQVDJKMnJHb2cyclV4bkorekNNMTFNN0RlTzBYTTJubnk0dVJZUFBrOXcyRVh6ZnZ0ZHZpZVlVLzVSQjRSRG01VEd4SGhHWFZaVWdhYzVBZ01CQUFFd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dJQkFGdDJYR2QzazVHcGJPMUVVbTN1NjB6VDFmRTZ1NnBPc2NwMTU2azVWbnNIZ2FIUkhkSUFQTkxlTE5tUjd5NU9uclhiaDEzQ3JHd1UxcTg0ampKWHB2K3YxNHhVQ2M1aTAxeW9wRlRRRkxyNEE3TkhwMm5OWWZOaGhJVlNGQWdXNDNFZmxKZmxiTEVlbENKenhMbFdiNUJvRHNaZWVObUVRc1hJTTFtSjI2UjNyMGR6c0hCYjB1eSs4TE5SMWdkVnFkamhDOEJMeTNnaDQrQld1aWR5Wk50MDdMdmVEc1NGVzVyY2o1d1JyU3g5aFhQSXlWcGpRU2xqTnZZN01WVG91cUp6TkFBUU1zVEtrWFBrVFhsZENvcDlRbzlVUGtIUlJtMGw3TEx0ZGFPb1hyY3QwWW1vY2Y4enhmOWJGTml3OWY0V1JZUU02c01oenQ4K3Mvb0RpbG80UWhjVWdlSkVpRVBFU2k2eW5ZVFY2MlNIQTRlTXVuVUo1ZGxDYVJuRmlSOURUSW1GYTVJUnppZTMyNi9uVy9TUENhS2MveXJGSWloTU1qSm9TQVBocFRiL0s2eUhPVUc4citLaVF1dDdOenFHVjMwMXBROXU2MmRHTDVPaTFWWG1DRmxFMnJhbVpzMTVCTk9VeUFvMkNCYlJKZzNqS2NkdS84UUM2b2pqRHZRODYzKzdMUHRuNzR3SkM1UnBVSnNTMEdoUVdncTVwQVhPM3dBNjFVb2J4aTZNa09wQ0MwekJXeC9kNENxcFM0ajRoRmd4V0JUWFg0OGloUHUraEl4SUYvQXhicXRQdnFMTUV4Vy94WklUbjZBcnBXeVE5ZTRTVVZyM24zRjMzYXAxWGREeVowdndGY20xOEpRQXRzdlhUNnFDTHJXT1huSFVnZm4vK1ZpdWhhdXRoRGF0YViklgTqgoJOmKStoUtEYtDXOo7EaRMNqRsZMHRZIp90o1lBAAAAKjJq3PAM70bQk5KY1sSoSnIAIKcQDs0jnxSbMObTtsbSfd-nQAT-fttB8eqoFO2yyfefpQECAyYgASFYIFELGCRbGZ0VfQUdtUbTw7vq-mREVUp3QmUYG3IvK1ppIlggLQcTtN3YB2nRGLaQhbnlKggk6D_s5Nub5SajLm2CjsA","clientDataJSON":"eyJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLnNwb21reS1sYWJzLmNvbSIsImNoYWxsZW5nZSI6IlRadFFKQTRBSENUbTN4UGpGTUNXa2NUZmFnNHJ5RklocEh1Qm1BWHNZZ00iLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"},"type":"public-key"}';

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
