<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Tests\Functional;

use Base64Url\Base64Url;
use Prophecy\Argument;
use Symfony\Component\HttpFoundation\Request;
use Webauthn\AttestedCredentialData;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\CredentialRepository;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * @group functional
 * @group Fido2
 */
class AssertionTest extends Fido2TestCase
{
    /**
     * @test
     */
    public function anAssertionCanBeVerified()
    {
        $publicKeyCredentialRequestOptions = new PublicKeyCredentialRequestOptions(
            \Safe\base64_decode('G0JbLLndef3a0Iy3S2sSQA8uO4SO/ze6FZMAuPI6+xI=', true),
            60000,
            'localhost',
            [
                new PublicKeyCredentialDescriptor(
                    PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                    Base64Url::decode('eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w')
                ),
            ],
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            new AuthenticationExtensionsClientInputs()
        );

        $publicKeyCredential = $this->getPublicKeyCredentialLoader()->load('{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"public-key","rawId":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MBAAAAew==","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ==","signature":"MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=","userHandle":null}}');

        static::assertInstanceOf(AuthenticatorAssertionResponse::class, $publicKeyCredential->getResponse());

        $credentialRepository = $this->prophesize(CredentialRepository::class);
        $credentialRepository->has(\Safe\base64_decode('eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==', true))->willReturn(true);
        $credentialRepository->get(\Safe\base64_decode('eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==', true))->willReturn(
            new AttestedCredentialData(
                \Safe\base64_decode('AAAAAAAAAAAAAAAAAAAAAA==', true),
                \Safe\base64_decode('eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==', true),
                \Safe\base64_decode('pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=', true)
            )
        );
        $credentialRepository->getCounterFor(\Safe\base64_decode('eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==', true))->willReturn(100);
        $credentialRepository->updateCounterFor(\Safe\base64_decode('eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==', true), Argument::any())->shouldBeCalled();

        $request = new Request();

        $this->getAuthenticatorAssertionResponseValidator($credentialRepository->reveal())->check(
            $publicKeyCredential->getRawId(),
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialRequestOptions,
            $request
        );
    }

    /**
     * @test
     */
    public function anAssertionWithTokenBindingCanBeVerified()
    {
        $publicKeyCredentialRequestOptions = new PublicKeyCredentialRequestOptions(
            \Safe\base64_decode('5rCH1TZzlhWn1ux5QyEFSZlmoYiKJm84FHxJZu1Zk4s=', true),
            60000,
            'webauthn.morselli.fr',
            [
                new PublicKeyCredentialDescriptor(
                    PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                    \Safe\base64_decode('+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYag==', true)
                ),
            ],
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            new AuthenticationExtensionsClientInputs()
        );

        $publicKeyCredential = $this->getPublicKeyCredentialLoader()->load('{"id":"-uZVS9-4JgjAYI49YhdzTgHmbn638-ZNSvC0UtHkWTVS-CtTjnaSbqtzdzijByOAvEAsh-TaQJAr43FRj-dYag","type":"public-key","rawId":"+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYag==","response":{"authenticatorData":"ytRu25lhUyPmYiS9/oq8XVnMLSBjAp3j6bJCBIkJQ7YFAAAAlA==","clientDataJSON":"ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5nZXQiLA0KCSJjaGFsbGVuZ2UiIDogIjVyQ0gxVFp6bGhXbjF1eDVReUVGU1psbW9ZaUtKbTg0Rkh4Slp1MVprNHMiLA0KCSJvcmlnaW4iIDogImh0dHBzOi8vd2ViYXV0aG4ubW9yc2VsbGkuZnIiLA0KCSJ0b2tlbkJpbmRpbmciIDogDQoJew0KCQkic3RhdHVzIiA6ICJzdXBwb3J0ZWQiDQoJfQ0KfQ==","signature":"MEUCIQCqFeffY4MT0dI95aS4zMiKjEb33zA/xGy3k9LTWjhgXgIgT39F2NoCc7UNLOy9N6Xf6bC4E3j056ZGGrbXcLY4F/A=","userHandle":null}}');

        static::assertInstanceOf(AuthenticatorAssertionResponse::class, $publicKeyCredential->getResponse());

        $credentialRepository = $this->prophesize(CredentialRepository::class);
        $credentialRepository->has(\Safe\base64_decode('+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYag==', true))->willReturn(true);
        $credentialRepository->get(\Safe\base64_decode('+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYag==', true))->willReturn(
            new AttestedCredentialData(
                \Safe\base64_decode('+KAR84wKTRWABhcRH57cfQ==', true),
                \Safe\base64_decode('+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYag==', true),
                \Safe\base64_decode('pQECAyYgASFYIGCFVff/+Igs33wIEwEpwqui12XMF0tof8eDzwZNBX8eIlggcmwcE9F9W5ouuxlzKJbEJIxmUlmRHvBkyDhrqhn7Npw=', true)
            )
        );
        $credentialRepository->getCounterFor(\Safe\base64_decode('+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYag==', true))->willReturn(100);
        $credentialRepository->updateCounterFor(\Safe\base64_decode('+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYag==', true), Argument::any())->shouldBeCalled();

        $request = new Request([], [], [], [], [], ['HTTP_HOST' => 'localhost']);

        $this->getAuthenticatorAssertionResponseValidator($credentialRepository->reveal())->check(
            $publicKeyCredential->getRawId(),
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialRequestOptions,
            $request
        );
    }
}
