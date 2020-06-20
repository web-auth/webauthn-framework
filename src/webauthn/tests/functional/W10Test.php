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
use Prophecy\Argument;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Ramsey\Uuid\Uuid;
use Webauthn\AttestedCredentialData;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorData;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * @group functional
 * @group Fido2
 *
 * @internal
 */
class W10Test extends AbstractTestCase
{
    /**
     * @test
     * @dataProvider getAttestationCanBeVerifiedData
     */
    public function anAttestationCanBeVerified(string $publicKeyCredentialCreationOptionsData, string $publicKeyCredentialData, string $credentialId, string $host, string $rpIdHash, int $signCount): void
    {
        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::createFromString(
            $publicKeyCredentialCreationOptionsData
        );
        $publicKeyCredential = $this->getPublicKeyCredentialLoader()->load($publicKeyCredentialData);
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $publicKeyCredential->getResponse());
        $credentialRepository = $this->prophesize(PublicKeyCredentialSourceRepository::class);
        $credentialRepository->findOneByCredentialId($credentialId)->willReturn(null);
        $uri = $this->prophesize(UriInterface::class);
        $uri->getHost()->willReturn($host);
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getUri()->willReturn($uri->reveal());
        $publicKeyCredentialSource = $this->getAuthenticatorAttestationResponseValidator($credentialRepository->reveal())->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request->reveal()
        );
        $publicKeyCredentialDescriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor(['usb']);
        static::assertEquals($credentialId, Base64Url::decode($publicKeyCredential->getId()));
        static::assertEquals($credentialId, $publicKeyCredentialDescriptor->getId());
        static::assertEquals(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $publicKeyCredentialDescriptor->getType());
        static::assertEquals(['usb'], $publicKeyCredentialDescriptor->getTransports());
        /** @var AuthenticatorData $authenticatorData */
        $authenticatorData = $publicKeyCredential->getResponse()->getAttestationObject()->getAuthData();
        static::assertEquals($rpIdHash, $authenticatorData->getRpIdHash());
        static::assertTrue($authenticatorData->isUserPresent());
        static::assertTrue($authenticatorData->isUserVerified());
        static::assertTrue($authenticatorData->hasAttestedCredentialData());
        static::assertEquals(0, $authenticatorData->getReservedForFutureUse1());
        static::assertEquals(0, $authenticatorData->getReservedForFutureUse2());
        static::assertEquals($signCount, $authenticatorData->getSignCount());
        static::assertInstanceOf(AttestedCredentialData::class, $authenticatorData->getAttestedCredentialData());
        static::assertFalse($authenticatorData->hasExtensions());

        if (PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE === $publicKeyCredentialCreationOptions->getAttestation()) {
            static::assertEquals('00000000-0000-0000-0000-000000000000', $publicKeyCredentialSource->getAaguid()->toString());
            static::assertEquals('none', $publicKeyCredentialSource->getAttestationType());
            static::assertInstanceOf(EmptyTrustPath::class, $publicKeyCredentialSource->getTrustPath());
        }
    }

    public function getAttestationCanBeVerifiedData(): array
    {
        return [
            [
                '{"rp":{"name":"Webauthn Demo"},"pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],"challenge":"XKADkZSW9B4h0Fek8KbhQun3m4dfJYN3ci9wdXDNJvU=","attestation":"direct","user":{"name":"test**","id":"ZjZlYWJjNGItYjkyYi00YzI0LTg2N2MtZWZjYmE4OGNjOTRm","displayName":"test**"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":60000}',
                '{"id":"WsVEgVplFhLkRd68yW3KAIyVJ90ZsQOHFjnL71YirSY","type":"public-key","rawId":"WsVEgVplFhLkRd68yW3KAIyVJ90ZsQOHFjnL71YirSY=","response":{"clientDataJSON":"ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5jcmVhdGUiLA0KCSJjaGFsbGVuZ2UiIDogIlhLQURrWlNXOUI0aDBGZWs4S2JoUXVuM200ZGZKWU4zY2k5d2RYRE5KdlUiLA0KCSJvcmlnaW4iIDogImh0dHBzOi8vd2ViYXV0aG4uc3BvbWt5LWxhYnMuY29tIiwNCgkidG9rZW5CaW5kaW5nIiA6IA0KCXsNCgkJInN0YXR1cyIgOiAic3VwcG9ydGVkIg0KCX0NCn0=","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZ5YE6oKCTpikraFLRGLQ1zqOxGkTDakbGTB0WSKfdKNZRQAAAABgKLAXsdRMArSzr82vyWuyACBaxUSBWmUWEuRF3rzJbcoAjJUn3RmxA4cWOcvvViKtJqQBAwM5AQAgWQEAv5VUWjpRGBvp2zawiX2JKC9WSDvVxlLfqNqU1EYsdN6iNg16FFF/0EHkt7tJz9wkwC3Cx5vYFyblUw7UF5m8qS579OcGRjvb6MHj+MQFuOKCoowBMY/VjuF+TT14deKMuWtShT2MCab1gtfnkuGAlEcu2CASvAwtbEPKZ2JkaouWWaJ3hDOYTXWYgCgtM5DqqnN9JUZjXrgmAfQC82SYh6ZAV+MQ2s4RG2jP/dvEt235oFSIkr3JEqhStQvJ+CFmjVk67oFtofcISax44CynCd2Lr89inWU1B0JwSB1oyuLPq5HCQuSmFed/piGjVfFgCbN0tCXJkAGufkDXE3J4xSFDAQAB"}}',
                base64_decode('WsVEgVplFhLkRd68yW3KAIyVJ90ZsQOHFjnL71YirSY=', true),
                'webauthn.spomky-labs.com',
                hex2bin('9604ea82824e98a4ada14b4462d0d73a8ec469130da91b19307459229f74a359'),
                0,
            ],
            [
                '{"rp":{"name":"Webauthn Demo","id":"webauthn.spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-46},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39}],"challenge":"8zaIzbt6jRK-dgL-QbWeuo2jkIeRC4OB89z7ZbKbucY","attestation":"none","user":{"name":"11","id":"N2Q3ZTQ2ZTktMzI5Yy00YzE0LWI5MWYtMDYyMWYyOTIyYWQ4","displayName":"éé1"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":60000}',
                '{"id":"OiAPhrzVRTolk1HfuApGPO9-ZfB7t0txSSAc2evu-p3F5sr_f0qAHg4UJpv7L7146VDVZXTiko36s4rJN4tcmA","type":"public-key","rawId":"OiAPhrzVRTolk1HfuApGPO9+ZfB7t0txSSAc2evu+p3F5sr/f0qAHg4UJpv7L7146VDVZXTiko36s4rJN4tcmA==","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiI4emFJemJ0NmpSSy1kZ0wtUWJXZXVvMmprSWVSQzRPQjg5ejdaYktidWNZIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5zcG9ta3ktbGFicy5jb20iLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAPrFFPc+JNPbQS9VLMZ0g8WC5cy7c0pCmd7acJmIY7hpAiAhW+5xovldQQixw/nAqdx5yTCffdrjBn9XfaGYhpxFLmN4NWOBWQLCMIICvjCCAaagAwIBAgIEdIb9wjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk1NTAwMzg0MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJVd8633JH0xde/9nMTzGk6HjrrhgQlWYVD7OIsuX2Unv1dAmqWBpQ0KxS8YRFwKE1SKE1PIpOWacE5SO8BN6+2jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER+e3H0wDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMVxIgOaaUn44Zom9af0KqG9J655OhUVBVW+q0As6AIod3AH5bHb2aDYakeIyyBCnnGMHTJtuekbrHbXYXERIn4aKdkPSKlyGLsA/A+WEi+OAfXrNVfjhrh7iE6xzq0sg4/vVJoywe4eAJx0fS+Dl3axzTTpYl71Nc7p/NX6iCMmdik0pAuYJegBcTckE3AoYEg4K99AM/JaaKIblsbFh8+3LxnemeNf7UwOczaGGvjS6UzGVI0Odf9lKcPIwYhuTxM5CaNMXTZQ7xq4/yTfC3kPWtE4hFT34UJJflZBiLrxG4OsYxkHw/n5vKgmpspB3GfYuYTWhkDKiE8CYtyg87mhhdXRoRGF0YVjElgTqgoJOmKStoUtEYtDXOo7EaRMNqRsZMHRZIp90o1lFAAABhvigEfOMCk0VgAYXER+e3H0AQDogD4a81UU6JZNR37gKRjzvfmXwe7dLcUkgHNnr7vqdxebK/39KgB4OFCab+y+9eOlQ1WV04pKN+rOKyTeLXJilAQIDJiABIVgg7EAfa9hDOFV9meRyhpqEWhLWwhuZjCEs2eX6RN4TnusiWCD/H1u+zBIuH79akbnFHgEHMEy0FbNaCZwsjAxguhyQ7Q=="}}',
                hex2bin('3a200f86bcd5453a259351dfb80a463cef7e65f07bb74b7149201cd9ebeefa9dc5e6caff7f4a801e0e14269bfb2fbd78e950d56574e2928dfab38ac9378b5c98'),
                'webauthn.spomky-labs.com',
                hex2bin('9604ea82824e98a4ada14b4462d0d73a8ec469130da91b19307459229f74a359'),
                390,
            ],
            [
                '{"rp":{"name":"Webauthn Demo","id":"webauthn.spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-46},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39}],"challenge":"33Hr5HpypBGbGvb2KNbyXft2z12eKUXPP9nYubuQwe0","attestation":"none","user":{"name":"55","id":"ZDZhOGNhMTAtNDhhZC00YmY1LTkyYWItZmYzOTlmNDZjY2Ew","displayName":"555"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":60000}',
                '{"id":"C2e2qx0JB7d0vWn25VUP6R8TGo5Id7Q6QX4zhTiuAP31YAwGO9yRhV-jxiHp0tIfzuec-UcgUAgnuBpc8eL_XQ","type":"public-key","rawId":"C2e2qx0JB7d0vWn25VUP6R8TGo5Id7Q6QX4zhTiuAP31YAwGO9yRhV+jxiHp0tIfzuec+UcgUAgnuBpc8eL/XQ==","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiIzM0hyNUhweXBCR2JHdmIyS05ieVhmdDJ6MTJlS1VYUFA5bll1YnVRd2UwIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5zcG9ta3ktbGFicy5jb20iLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgB6C51QpoEFbsT2QoYk3NZnBqcHQXLMCt7gmFmqqJK3oCIEp3qKMLOweaj6zeZuvxnxgNo5ZmO6JgZt1LKRWUd9fpY3g1Y4FZAsAwggK8MIIBpKADAgECAgQDrfASMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjBtMQswCQYDVQQGEwJTRTESMBAGA1UECgwJWXViaWNvIEFCMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMSYwJAYDVQQDDB1ZdWJpY28gVTJGIEVFIFNlcmlhbCA2MTczMDgzNDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBmeh5wWLbfcOe5KQqBGFqWzCf7KCS92vglI+W1ulcrkzGXNVKBZz73HybMbKx1sGER5wsBh9BiqlUtZaiwc+hejbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS43MBMGCysGAQQBguUcAgEBBAQDAgQwMCEGCysGAQQBguUcAQEEBBIEEPormdyeOUJXj5JKMNI8QRgwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAKOuzZ/7R2PDiievKn/bYB1fGDprlfLFyjJscOMq7vYTZI32oMawhlJ8PLfwMMWv9sXWzbmOiK7tYDq3KUoDQeYQOWh4lcmJaO/uHYDPb+yKpack4uJzhcTWUAKElLZcCqRKT1UUZ6WDdIs6KJ+sF6355t1DAAv7ZAWtxHsmtdFAb2RTLvo7ZVxKBt09E6wd85h7LBquFqXJVJn7o45gr9D8Msho4LSNeueTObbKYxAVCUEAjKyth4QzXDGIVvAO36UBxtw4S0cR/lmVaLvmdTOVafxtLH/kU7hNtnmEgRxSIZGmIgEQxFmU4ibhkhtnJyf+8k4VFNWmzRXRLjKC0N2hhdXRoRGF0YVjElgTqgoJOmKStoUtEYtDXOo7EaRMNqRsZMHRZIp90o1lFAAAAhformdyeOUJXj5JKMNI8QRgAQAtntqsdCQe3dL1p9uVVD+kfExqOSHe0OkF+M4U4rgD99WAMBjvckYVfo8Yh6dLSH87nnPlHIFAIJ7gaXPHi/12lAQIDJiABIVgg55k5XWCizey2Eg3Wg1MArH1DFh9NRx1T5vbIZZWLxQoiWCAqZUDarejYw8p9BYLGckwg13MwLPHKjYCIOFDf2wY7SQ=="}}',
                hex2bin('0b67b6ab1d0907b774bd69f6e5550fe91f131a8e4877b43a417e338538ae00fdf5600c063bdc91855fa3c621e9d2d21fcee79cf94720500827b81a5cf1e2ff5d'),
                'webauthn.spomky-labs.com',
                hex2bin('9604ea82824e98a4ada14b4462d0d73a8ec469130da91b19307459229f74a359'),
                133,
            ],
        ];
    }

    /**
     * @test
     */
    public function anAssertionCanBeVerified(): void
    {
        $publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions::createFromString(
            '{"challenge":"w+BeaUTZZnYMzvUB5GWUpiT1WYOnr9iCGUt5irUiUko=","userVerification":"preferred","allowCredentials":[{"type":"public-key","id":"6oRgydKXdC3LtZBDoAXxKnWte68elEQejDrYOV9x+18="}],"timeout":60000}'
        );
        $publicKeyCredential = $this->getPublicKeyCredentialLoader()->load(
            '{"id":"6oRgydKXdC3LtZBDoAXxKnWte68elEQejDrYOV9x-18","type":"public-key","rawId":"6oRgydKXdC3LtZBDoAXxKnWte68elEQejDrYOV9x+18=","response":{"authenticatorData":"lgTqgoJOmKStoUtEYtDXOo7EaRMNqRsZMHRZIp90o1kFAAAABA==","clientDataJSON":"ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5nZXQiLA0KCSJjaGFsbGVuZ2UiIDogInctQmVhVVRaWm5ZTXp2VUI1R1dVcGlUMVdZT25yOWlDR1V0NWlyVWlVa28iLA0KCSJvcmlnaW4iIDogImh0dHBzOi8vd2ViYXV0aG4uc3BvbWt5LWxhYnMuY29tIiwNCgkidG9rZW5CaW5kaW5nIiA6IA0KCXsNCgkJInN0YXR1cyIgOiAic3VwcG9ydGVkIg0KCX0NCn0=","signature":"lV7pKH+0rVaaWC5ZoQIMSW1EjeIELfUTKcplaSW65I8rH7U38qVoTYyvxQiZwtQsqKgXOMQYJ6n1JV+is3yi8wOjxkkmR/bLPPssLz7Za1ooSAJ+R1JKTYsmsozpTmouCVtBN4Il92Zrhy9sOD3pVUjHUJaXaEsV2dReqEamwt9+VLQiD0fJwYrqiyWETEybGqJSj7p2Zb0BVOcevlPCj3tX84DreZMW7lkYE6PyuJCmi7eR/kKq2N+ohvH6H3aHloQ+kgSb2L2gJn1hjs5Z3JxMvrwmnj0Vx1J2AMWrQyuBeBblJN3UP3Wbk16e+8Bq8HC9W6JG9qgqTyR1wJx0Yw==","userHandle":"ZWUxM2Q0ZjEtNDg2My00N2RkLWE0MDctMDk3Y2I0OWFjODIy"}}'
        );
        static::assertInstanceOf(AuthenticatorAssertionResponse::class, $publicKeyCredential->getResponse());
        $publicKeyCredentialSource = $this->prophesize(PublicKeyCredentialSource::class);
        $publicKeyCredentialSource->getUserHandle()->willReturn('ee13d4f1-4863-47dd-a407-097cb49ac822');
        $publicKeyCredentialSource->getCounter()->willReturn(0);
        $publicKeyCredentialSource->setCounter(Argument::is(4))->will(function (): void {});
        $publicKeyCredentialSource->getAttestedCredentialData()->willReturn(new AttestedCredentialData(
            Uuid::fromBytes(base64_decode('YCiwF7HUTAK0s6/Nr8lrsg==', true)),
            base64_decode('6oRgydKXdC3LtZBDoAXxKnWte68elEQejDrYOV9x+18=', true),
            base64_decode('pAEDAzkBACBZAQDwn2Ee7V+9GNDn2iCU2plQnIVmZG/vOiXSHb9TQzC5806bGzLV918+1SLFhMhlX5jua2rdXt65nYw9Eln7mbmVxLBDmEm2wod6wP2HinC9HPsYwr75tMRakLMNFfH4Xx4lEsjulRmv68yl/N8XH64X8LKe2GBxjqcuJR+c3LbW4D5dWt/1pGL8fS1UbO3abA/d3IeEsP8RpEz5eVo6qBhb4r0VTo2NMeq75saBHIj4whqo6qsRqRvBmK2d9NAecBFFRIQ31NUtEQZPqXOzkbXGehDi7c3YJPBkTW9kMqcosob9Vlru+vVab+1PnFRdqaklR1UtmhrWte/wB61Hm3xdIUMBAAE=', true)
        ));

        $credentialRepository = $this->prophesize(PublicKeyCredentialSourceRepository::class);
        $credentialRepository->findOneByCredentialId(base64_decode('6oRgydKXdC3LtZBDoAXxKnWte68elEQejDrYOV9x+18=', true))->willReturn($publicKeyCredentialSource->reveal());
        $credentialRepository->saveCredentialSource(Argument::type(PublicKeyCredentialSource::class))->will(function (): void {});

        $uri = $this->prophesize(UriInterface::class);
        $uri->getHost()->willReturn('webauthn.spomky-labs.com');
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getUri()->willReturn($uri->reveal());
        $this->getAuthenticatorAssertionResponseValidator($credentialRepository->reveal())->check(
            $publicKeyCredential->getRawId(),
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialRequestOptions,
            $request->reveal(),
            'ee13d4f1-4863-47dd-a407-097cb49ac822'
        );
    }
}
