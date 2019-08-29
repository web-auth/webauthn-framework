<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
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

/**
 * @group functional
 * @group Fido2
 * TODO: when bug #56 is resolved, new tests should be added
 */
class W10Test extends AbstractTestCase
{
    /**
     * @test
     */
    public function anAttestationWithTokenBindingCanBeVerified(): void
    {
        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::createFromString(
            '{"rp":{"name":"Webauthn Demo"},"pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],"challenge":"XKADkZSW9B4h0Fek8KbhQun3m4dfJYN3ci9wdXDNJvU=","attestation":"direct","user":{"name":"test**","id":"ZjZlYWJjNGItYjkyYi00YzI0LTg2N2MtZWZjYmE4OGNjOTRm","displayName":"test**"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":60000}'
        );
        $publicKeyCredential = $this->getPublicKeyCredentialLoader()->load('{"id":"WsVEgVplFhLkRd68yW3KAIyVJ90ZsQOHFjnL71YirSY","type":"public-key","rawId":"WsVEgVplFhLkRd68yW3KAIyVJ90ZsQOHFjnL71YirSY=","response":{"clientDataJSON":"ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5jcmVhdGUiLA0KCSJjaGFsbGVuZ2UiIDogIlhLQURrWlNXOUI0aDBGZWs4S2JoUXVuM200ZGZKWU4zY2k5d2RYRE5KdlUiLA0KCSJvcmlnaW4iIDogImh0dHBzOi8vd2ViYXV0aG4uc3BvbWt5LWxhYnMuY29tIiwNCgkidG9rZW5CaW5kaW5nIiA6IA0KCXsNCgkJInN0YXR1cyIgOiAic3VwcG9ydGVkIg0KCX0NCn0=","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZ5YE6oKCTpikraFLRGLQ1zqOxGkTDakbGTB0WSKfdKNZRQAAAABgKLAXsdRMArSzr82vyWuyACBaxUSBWmUWEuRF3rzJbcoAjJUn3RmxA4cWOcvvViKtJqQBAwM5AQAgWQEAv5VUWjpRGBvp2zawiX2JKC9WSDvVxlLfqNqU1EYsdN6iNg16FFF/0EHkt7tJz9wkwC3Cx5vYFyblUw7UF5m8qS579OcGRjvb6MHj+MQFuOKCoowBMY/VjuF+TT14deKMuWtShT2MCab1gtfnkuGAlEcu2CASvAwtbEPKZ2JkaouWWaJ3hDOYTXWYgCgtM5DqqnN9JUZjXrgmAfQC82SYh6ZAV+MQ2s4RG2jP/dvEt235oFSIkr3JEqhStQvJ+CFmjVk67oFtofcISax44CynCd2Lr89inWU1B0JwSB1oyuLPq5HCQuSmFed/piGjVfFgCbN0tCXJkAGufkDXE3J4xSFDAQAB"}}');
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $publicKeyCredential->getResponse());
        $credentialRepository = $this->prophesize(PublicKeyCredentialSourceRepository::class);
        $credentialRepository->findOneByCredentialId(base64_decode('WsVEgVplFhLkRd68yW3KAIyVJ90ZsQOHFjnL71YirSY=', true))->willReturn(null);
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
        static::assertEquals(base64_decode('WsVEgVplFhLkRd68yW3KAIyVJ90ZsQOHFjnL71YirSY=', true), Base64Url::decode($publicKeyCredential->getId()));
        static::assertEquals(base64_decode('WsVEgVplFhLkRd68yW3KAIyVJ90ZsQOHFjnL71YirSY=', true), $publicKeyCredentialDescriptor->getId());
        static::assertEquals(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $publicKeyCredentialDescriptor->getType());
        static::assertEquals(['usb'], $publicKeyCredentialDescriptor->getTransports());
        /** @var AuthenticatorData $authenticatorData */
        $authenticatorData = $publicKeyCredential->getResponse()->getAttestationObject()->getAuthData();
        static::assertEquals(hex2bin('9604ea82824e98a4ada14b4462d0d73a8ec469130da91b19307459229f74a359'), $authenticatorData->getRpIdHash());
        static::assertTrue($authenticatorData->isUserPresent());
        static::assertTrue($authenticatorData->isUserVerified());
        static::assertTrue($authenticatorData->hasAttestedCredentialData());
        static::assertEquals(0, $authenticatorData->getReservedForFutureUse1());
        static::assertEquals(0, $authenticatorData->getReservedForFutureUse2());
        static::assertEquals(0, $authenticatorData->getSignCount());
        static::assertInstanceOf(AttestedCredentialData::class, $authenticatorData->getAttestedCredentialData());
        static::assertFalse($authenticatorData->hasExtensions());
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
        $publicKeyCredentialSource->setCounter(Argument::is(4))->will(function () {});
        $publicKeyCredentialSource->getAttestedCredentialData()->willReturn(new AttestedCredentialData(
            Uuid::fromBytes(base64_decode('YCiwF7HUTAK0s6/Nr8lrsg==', true)),
            base64_decode('6oRgydKXdC3LtZBDoAXxKnWte68elEQejDrYOV9x+18=', true),
            base64_decode('pAEDAzkBACBZAQDwn2Ee7V+9GNDn2iCU2plQnIVmZG/vOiXSHb9TQzC5806bGzLV918+1SLFhMhlX5jua2rdXt65nYw9Eln7mbmVxLBDmEm2wod6wP2HinC9HPsYwr75tMRakLMNFfH4Xx4lEsjulRmv68yl/N8XH64X8LKe2GBxjqcuJR+c3LbW4D5dWt/1pGL8fS1UbO3abA/d3IeEsP8RpEz5eVo6qBhb4r0VTo2NMeq75saBHIj4whqo6qsRqRvBmK2d9NAecBFFRIQ31NUtEQZPqXOzkbXGehDi7c3YJPBkTW9kMqcosob9Vlru+vVab+1PnFRdqaklR1UtmhrWte/wB61Hm3xdIUMBAAE=', true)
        ));

        $credentialRepository = $this->prophesize(PublicKeyCredentialSourceRepository::class);
        $credentialRepository->findOneByCredentialId(base64_decode('6oRgydKXdC3LtZBDoAXxKnWte68elEQejDrYOV9x+18=', true))->willReturn($publicKeyCredentialSource->reveal());
        $credentialRepository->saveCredentialSource(Argument::type(PublicKeyCredentialSource::class))->will(function () {});

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
