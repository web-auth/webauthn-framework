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
use Http\Mock\Client;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Webauthn\AttestedCredentialData;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorData;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CredentialRepository;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Zend\Diactoros\Response;

/**
 * @group functional
 * @group Fido2
 */
class AttestationTest extends AbstractTestCase
{
    /**
     * @test
     */
    public function aNoneAttestationCanBeVerified(): void
    {
        $publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity('My Application'),
            new PublicKeyCredentialUserEntity('test@foo.com', random_bytes(64), 'Test PublicKeyCredentialUserEntity'),
            \Safe\base64_decode('9WqgpRIYvGMCUYiFT20o1U7hSD193k11zu4tKP7wRcrE26zs1zc4LHyPinvPGS86wu6bDvpwbt8Xp2bQ3VBRSQ==', true),
            [
                new PublicKeyCredentialParameters('public-key', PublicKeyCredentialParameters::ALGORITHM_ES256),
            ],
            60000,
            [],
            new AuthenticatorSelectionCriteria(),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            new AuthenticationExtensionsClientInputs()
        );

        $publicKeyCredential = $this->getPublicKeyCredentialLoader()->load('{"id":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK","type":"public-key","rawId":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiI5V3FncFJJWXZHTUNVWWlGVDIwbzFVN2hTRDE5M2sxMXp1NHRLUDd3UmNyRTI2enMxemM0TEh5UGludlBHUzg2d3U2YkR2cHdidDhYcDJiUTNWQlJTUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjkSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAYJjIobiMfS7pLMMQTjIzBw3+hADjTsu6nVoWkEO3TrVYkdnFQfzDW2cVEYtnL4ErykiC295iEnvZTzRvbGIKI7mOYjYp2DoOoUVcZptFbLLjRtqZtfkSLkxfQ1LRCWRBCqUBAgMmIAEhWCAcPxwKyHADVjTgTsat4R/Jax6PWte50A8ZasMm4w6RxCJYILt0FCiGwC6rBrh3ySNy0yiUjZpNGAhW+aM9YYyYnUTJ"}}');

        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $publicKeyCredential->getResponse());

        $credentialRepository = $this->prophesize(CredentialRepository::class);
        $credentialRepository->has(\Safe\base64_decode('mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK', true))->willReturn(false);

        $uri = $this->prophesize(UriInterface::class);
        $uri->getHost()->willReturn('localhost');
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getUri()->willReturn($uri->reveal());


        $this->getAuthenticatorAttestationResponseValidator($credentialRepository->reveal(), new Client())->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request->reveal()
        );
    }

    /**
     * @test
     */
    public function aFidoU2FAttestationCanBeVerified(): void
    {
        $publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity('My Application'),
            new PublicKeyCredentialUserEntity('test@foo.com', random_bytes(64), 'Test PublicKeyCredentialUserEntity'),
            \Safe\base64_decode('pGRaBff9zpaw3CDAsggpOMRonJaqMXYjkvIGTPt3rHH+53RCW7LQ9l4NmGcv8dNZSNLDrvQDKaSNhFjviggcZA==', true),
            [
                new PublicKeyCredentialParameters('public-key', PublicKeyCredentialParameters::ALGORITHM_ES256),
            ],
            60000,
            [],
            new AuthenticatorSelectionCriteria(),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
            new AuthenticationExtensionsClientInputs()
        );

        $publicKeyCredential = $this->getPublicKeyCredentialLoader()->load('{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"public-key","rawId":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJwR1JhQmZmOXpwYXczQ0RBc2dncE9NUm9uSmFxTVhZamt2SUdUUHQzckhILTUzUkNXN0xROWw0Tm1HY3Y4ZE5aU05MRHJ2UURLYVNOaEZqdmlnZ2NaQSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=","attestationObject":"o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhALAccRlhFqq41JTqOC3cHkkN+O6ouvv4izWZY2W7NFh/AiBndeDPR6P2DZzia1sD4JFa87f3t/8bUgWzOsELduLkRWN4NWOBWQLCMIICvjCCAaagAwIBAgIEdIb9wjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk1NTAwMzg0MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJVd8633JH0xde/9nMTzGk6HjrrhgQlWYVD7OIsuX2Unv1dAmqWBpQ0KxS8YRFwKE1SKE1PIpOWacE5SO8BN6+2jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER+e3H0wDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMVxIgOaaUn44Zom9af0KqG9J655OhUVBVW+q0As6AIod3AH5bHb2aDYakeIyyBCnnGMHTJtuekbrHbXYXERIn4aKdkPSKlyGLsA/A+WEi+OAfXrNVfjhrh7iE6xzq0sg4/vVJoywe4eAJx0fS+Dl3axzTTpYl71Nc7p/NX6iCMmdik0pAuYJegBcTckE3AoYEg4K99AM/JaaKIblsbFh8+3LxnemeNf7UwOczaGGvjS6UzGVI0Odf9lKcPIwYhuTxM5CaNMXTZQ7xq4/yTfC3kPWtE4hFT34UJJflZBiLrxG4OsYxkHw/n5vKgmpspB3GfYuYTWhkDKiE8CYtyg87mhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQHh6Ls/2Yu/gZgch4yf7cfYeGtVmbCuCM1JoBo5IcjqHTxgMlKlKfwfclJH5V2N8h1rDbbK4Al0Nx4wCBVHmQfulAQIDJiABIVgglXnq9GsW6ygN/2GbeIOaWVzHFfPMrI71au4rDiRbHvMiWCD+erreXwgwlwh0oMlxdGH2GjPQv6dXA/U7GKXf+g1Biw=="}}');

        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $publicKeyCredential->getResponse());

        $credentialRepository = $this->prophesize(CredentialRepository::class);
        $credentialRepository->has(\Safe\base64_decode('eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==', true))->willReturn(false);

        $uri = $this->prophesize(UriInterface::class);
        $uri->getHost()->willReturn('localhost');
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getUri()->willReturn($uri->reveal());

        $this->getAuthenticatorAttestationResponseValidator($credentialRepository->reveal(), new Client())->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request->reveal()
        );
    }

    /**
     * @test
     */
    public function aPackedAttestationCanBeVerified(): void
    {
        $publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity('My Application'),
            new PublicKeyCredentialUserEntity('test@foo.com', random_bytes(64), 'Test PublicKeyCredentialUserEntity'),
            \Safe\base64_decode('32urRB1LDfyfYeU9myCPfrhrvNoVI27//+PWWYVxAISpIm3GqgX+jNudPgvOZy96UPNvEkCWCArW0jtpQZFGAg==', true),
            [
                new PublicKeyCredentialParameters('public-key', PublicKeyCredentialParameters::ALGORITHM_ES256),
            ],
            60000,
            [],
            new AuthenticatorSelectionCriteria(),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
            new AuthenticationExtensionsClientInputs()
        );

        $publicKeyCredential = $this->getPublicKeyCredentialLoader()->load('{"id":"xYw3gEj0LVL83JXz7oKL14XQjh9W1NMFrTALWI-lqXl7ndKW-n8JFYsBCuKbZA3zRAUxAZDHG_tXHsAi6TbO0Q","type":"public-key","rawId":"xYw3gEj0LVL83JXz7oKL14XQjh9W1NMFrTALWI+lqXl7ndKW+n8JFYsBCuKbZA3zRAUxAZDHG/tXHsAi6TbO0Q==","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiIzMnVyUkIxTERmeWZZZVU5bXlDUGZyaHJ2Tm9WSTI3X18tUFdXWVZ4QUlTcEltM0dxZ1gtak51ZFBndk9aeTk2VVBOdkVrQ1dDQXJXMGp0cFFaRkdBZyIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAOkogofSKvV0ma9Ejb3WH44tmXrUhSNK5qg7blgjR1n8AiEAuMsQaAsw27slMfM+wLfe4ozk+Mv8Rxdluhj59hLP4fxjeDVjgVkCwjCCAr4wggGmoAMCAQICBHSG/cIwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMG8xCzAJBgNVBAYTAlNFMRIwEAYDVQQKDAlZdWJpY28gQUIxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDE5NTUwMDM4NDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASVXfOt9yR9MXXv/ZzE8xpOh4664YEJVmFQ+ziLLl9lJ79XQJqlgaUNCsUvGERcChNUihNTyKTlmnBOUjvATevto2wwajAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTATBgsrBgEEAYLlHAIBAQQEAwIFIDAhBgsrBgEEAYLlHAEBBAQSBBD4oBHzjApNFYAGFxEfntx9MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBADFcSIDmmlJ+OGaJvWn9CqhvSeueToVFQVVvqtALOgCKHdwB+Wx29mg2GpHiMsgQp5xjB0ybbnpG6x212FxESJ+GinZD0ipchi7APwPlhIvjgH16zVX44a4e4hOsc6tLIOP71SaMsHuHgCcdH0vg5d2sc006WJe9TXO6fzV+ogjJnYpNKQLmCXoAXE3JBNwKGBIOCvfQDPyWmiiG5bGxYfPty8Z3pnjX+1MDnM2hhr40ulMxlSNDnX/ZSnDyMGIbk8TOQmjTF02UO8auP8k3wt5D1rROIRU9+FCSX5WQYi68RuDrGMZB8P5+byoJqbKQdxn2LmE1oZAyohPAmLcoPO5oYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAHz4oBHzjApNFYAGFxEfntx9AEDFjDeASPQtUvzclfPugovXhdCOH1bU0wWtMAtYj6WpeXud0pb6fwkViwEK4ptkDfNEBTEBkMcb+1cewCLpNs7RpQECAyYgASFYIBECPLnZwCFJ/2Pam0zUQOi4QQAwCKdAZ++36lPi7yvbIlgg4+9scyMxQeQjYGIgli1h5Sh2mlv8BwXwwQKUvbtS+KY="}}');

        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $publicKeyCredential->getResponse());

        $credentialRepository = $this->prophesize(CredentialRepository::class);
        $credentialRepository->has(\Safe\base64_decode('xYw3gEj0LVL83JXz7oKL14XQjh9W1NMFrTALWI+lqXl7ndKW+n8JFYsBCuKbZA3zRAUxAZDHG/tXHsAi6TbO0Q==', true))->willReturn(false);

        $uri = $this->prophesize(UriInterface::class);
        $uri->getHost()->willReturn('localhost');
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getUri()->willReturn($uri->reveal());

        $this->getAuthenticatorAttestationResponseValidator($credentialRepository->reveal(), new Client())->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request->reveal()
        );

        $publicKeyCredentialDescriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor(['usb']);

        static::assertEquals(\Safe\base64_decode('xYw3gEj0LVL83JXz7oKL14XQjh9W1NMFrTALWI+lqXl7ndKW+n8JFYsBCuKbZA3zRAUxAZDHG/tXHsAi6TbO0Q==', true), Base64Url::decode($publicKeyCredential->getId()));
        static::assertEquals(\Safe\base64_decode('xYw3gEj0LVL83JXz7oKL14XQjh9W1NMFrTALWI+lqXl7ndKW+n8JFYsBCuKbZA3zRAUxAZDHG/tXHsAi6TbO0Q==', true), $publicKeyCredentialDescriptor->getId());
        static::assertEquals(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $publicKeyCredentialDescriptor->getType());
        static::assertEquals(['usb'], $publicKeyCredentialDescriptor->getTransports());

        /** @var AuthenticatorData $authenticatorData */
        $authenticatorData = $publicKeyCredential->getResponse()->getAttestationObject()->getAuthData();

        static::assertEquals(\Safe\hex2bin('49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763'), $authenticatorData->getRpIdHash());
        static::assertTrue($authenticatorData->isUserPresent());
        static::assertFalse($authenticatorData->isUserVerified());
        static::assertTrue($authenticatorData->hasAttestedCredentialData());
        static::assertEquals(0, $authenticatorData->getReservedForFutureUse1());
        static::assertEquals(0, $authenticatorData->getReservedForFutureUse2());
        static::assertEquals(124, $authenticatorData->getSignCount());
        static::assertInstanceOf(AttestedCredentialData::class, $authenticatorData->getAttestedCredentialData());
        static::assertFalse($authenticatorData->hasExtensions());
    }

    /**
     * @test
     * @group FOO
     */
    public function anAndroidSafetyNetAttestationCanBeVerified(): void
    {
        $publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity('My Application'),
            new PublicKeyCredentialUserEntity('test@foo.com', random_bytes(64), 'Test PublicKeyCredentialUserEntity'),
            \Safe\base64_decode('kmns43CWVswbMovrKPkgd1lEpc6LZdfk0UQ/nuZbp00jW5C61PEW1dNaptZ0GkrIK9WRtaAXWkndIEEBgNICRw', true),
            [
                new PublicKeyCredentialParameters('public-key', PublicKeyCredentialParameters::ALGORITHM_ES256),
            ],
            60000,
            [],
            new AuthenticatorSelectionCriteria(),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
            new AuthenticationExtensionsClientInputs()
        );

        $publicKeyCredential = $this->getPublicKeyCredentialLoader()->load('{"id":"Ac8zKrpVWv9UCwxY1FyMqkESz2lV4CNwTk2-Hp19LgKbvh5uQ2_i6AMbTbTz1zcNapCEeiLJPlAAVM4L7AIow6I","type":"public-key","rawId":"Ac8zKrpVWv9UCwxY1FyMqkESz2lV4CNwTk2+Hp19LgKbvh5uQ2/i6AMbTbTz1zcNapCEeiLJPlAAVM4L7AIow6I=","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoia21uczQzQ1dWc3diTW92cktQa2dkMWxFcGM2TFpkZmswVVFfbnVaYnAwMGpXNUM2MVBFVzFkTmFwdFowR2tySUs5V1J0YUFYV2tuZElFRUJnTklDUnciLCJvcmlnaW4iOiJodHRwczpcL1wvd2ViYXV0aG4ubW9yc2VsbGkuZnIiLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJjb20uYW5kcm9pZC5jaHJvbWUifQ==","attestationObject":"o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaDE0Nzk5MDM3aHJlc3BvbnNlWRS9ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxHYTJwRFEwSkljV2RCZDBsQ1FXZEpVVkpZY205T01GcFBaRkpyUWtGQlFVRkJRVkIxYm5wQlRrSm5hM0ZvYTJsSE9YY3dRa0ZSYzBaQlJFSkRUVkZ6ZDBOUldVUldVVkZIUlhkS1ZsVjZSV1ZOUW5kSFFURlZSVU5vVFZaU01qbDJXako0YkVsR1VubGtXRTR3U1VaT2JHTnVXbkJaTWxaNlRWSk5kMFZSV1VSV1VWRkVSWGR3U0ZaR1RXZFJNRVZuVFZVNGVFMUNORmhFVkVVMFRWUkJlRTFFUVROTlZHc3dUbFp2V0VSVVJUVk5WRUYzVDFSQk0wMVVhekJPVm05M1lrUkZURTFCYTBkQk1WVkZRbWhOUTFaV1RYaEZla0ZTUW1kT1ZrSkJaMVJEYTA1b1lrZHNiV0l6U25WaFYwVjRSbXBCVlVKblRsWkNRV05VUkZVeGRtUlhOVEJaVjJ4MVNVWmFjRnBZWTNoRmVrRlNRbWRPVmtKQmIxUkRhMlIyWWpKa2MxcFRRazFVUlUxNFIzcEJXa0puVGxaQ1FVMVVSVzFHTUdSSFZucGtRelZvWW0xU2VXSXliR3RNYlU1MllsUkRRMEZUU1hkRVVWbEtTMjlhU1doMlkwNUJVVVZDUWxGQlJHZG5SVkJCUkVORFFWRnZRMmRuUlVKQlRtcFlhM293WlVzeFUwVTBiU3N2UnpWM1QyOHJXRWRUUlVOeWNXUnVPRGh6UTNCU04yWnpNVFJtU3pCU2FETmFRMWxhVEVaSWNVSnJOa0Z0V2xaM01rczVSa2N3VHpseVVsQmxVVVJKVmxKNVJUTXdVWFZ1VXpsMVowaEROR1ZuT1c5MmRrOXRLMUZrV2pKd09UTllhSHAxYmxGRmFGVlhXRU40UVVSSlJVZEtTek5UTW1GQlpucGxPVGxRVEZNeU9XaE1ZMUYxV1ZoSVJHRkROMDlhY1U1dWIzTnBUMGRwWm5NNGRqRnFhVFpJTDNob2JIUkRXbVV5YkVvck4wZDFkSHBsZUV0d2VIWndSUzkwV2xObVlsazVNRFZ4VTJ4Q2FEbG1jR293TVRWamFtNVJSbXRWYzBGVmQyMUxWa0ZWZFdWVmVqUjBTMk5HU3pSd1pYWk9UR0Y0UlVGc0swOXJhV3hOZEVsWlJHRmpSRFZ1Wld3MGVFcHBlWE0wTVROb1lXZHhWekJYYUdnMVJsQXpPV2hIYXpsRkwwSjNVVlJxWVhwVGVFZGtkbGd3YlRaNFJsbG9hQzh5VmsxNVdtcFVORXQ2VUVwRlEwRjNSVUZCWVU5RFFXeG5kMmRuU2xWTlFUUkhRVEZWWkVSM1JVSXZkMUZGUVhkSlJtOUVRVlJDWjA1V1NGTlZSVVJFUVV0Q1oyZHlRbWRGUmtKUlkwUkJWRUZOUW1kT1ZraFNUVUpCWmpoRlFXcEJRVTFDTUVkQk1WVmtSR2RSVjBKQ1VYRkNVWGRIVjI5S1FtRXhiMVJMY1hWd2J6UlhObmhVTm1veVJFRm1RbWRPVmtoVFRVVkhSRUZYWjBKVFdUQm1hSFZGVDNaUWJTdDRaMjU0YVZGSE5rUnlabEZ1T1V0NlFtdENaMmR5UW1kRlJrSlJZMEpCVVZKWlRVWlpkMHAzV1VsTGQxbENRbEZWU0UxQlIwZEhNbWd3WkVoQk5reDVPWFpaTTA1M1RHNUNjbUZUTlc1aU1qbHVUREprTUdONlJuWk5WRUZ5UW1kbmNrSm5SVVpDVVdOM1FXOVpabUZJVWpCalJHOTJURE5DY21GVE5XNWlNamx1VERKa2VtTnFTWFpTTVZKVVRWVTRlRXh0VG5sa1JFRmtRbWRPVmtoU1JVVkdha0ZWWjJoS2FHUklVbXhqTTFGMVdWYzFhMk50T1hCYVF6VnFZakl3ZDBsUldVUldVakJuUWtKdmQwZEVRVWxDWjFwdVoxRjNRa0ZuU1hkRVFWbExTM2RaUWtKQlNGZGxVVWxHUVhwQmRrSm5UbFpJVWpoRlMwUkJiVTFEVTJkSmNVRm5hR2cxYjJSSVVuZFBhVGgyV1ROS2MweHVRbkpoVXpWdVlqSTVia3d3WkZWVmVrWlFUVk0xYW1OdGQzZG5aMFZGUW1kdmNrSm5SVVZCWkZvMVFXZFJRMEpKU0RGQ1NVaDVRVkJCUVdSM1EydDFVVzFSZEVKb1dVWkpaVGRGTmt4TldqTkJTMUJFVjFsQ1VHdGlNemRxYW1RNE1FOTVRVE5qUlVGQlFVRlhXbVJFTTFCTVFVRkJSVUYzUWtsTlJWbERTVkZEVTFwRFYyVk1Tblp6YVZaWE5rTm5LMmRxTHpsM1dWUktVbnAxTkVocGNXVTBaVmswWXk5dGVYcHFaMGxvUVV4VFlta3ZWR2g2WTNweGRHbHFNMlJyTTNaaVRHTkpWek5NYkRKQ01HODNOVWRSWkdoTmFXZGlRbWRCU0ZWQlZtaFJSMjFwTDFoM2RYcFVPV1ZIT1ZKTVNTdDRNRm95ZFdKNVdrVldla0UzTlZOWlZtUmhTakJPTUVGQlFVWnRXRkU1ZWpWQlFVRkNRVTFCVW1wQ1JVRnBRbU5EZDBFNWFqZE9WRWRZVURJM09IbzBhSEl2ZFVOSWFVRkdUSGx2UTNFeVN6QXJlVXhTZDBwVlltZEpaMlk0WjBocWRuQjNNbTFDTVVWVGFuRXlUMll6UVRCQlJVRjNRMnR1UTJGRlMwWlZlVm8zWmk5UmRFbDNSRkZaU2t0dldrbG9kbU5PUVZGRlRFSlJRVVJuWjBWQ1FVazVibFJtVWt0SlYyZDBiRmRzTTNkQ1REVTFSVlJXTm10aGVuTndhRmN4ZVVGak5VUjFiVFpZVHpReGExcDZkMG8yTVhkS2JXUlNVbFF2VlhORFNYa3hTMFYwTW1Nd1JXcG5iRzVLUTBZeVpXRjNZMFZYYkV4UldUSllVRXg1Um1wclYxRk9ZbE5vUWpGcE5GY3lUbEpIZWxCb2RETnRNV0kwT1doaWMzUjFXRTAyZEZnMVEzbEZTRzVVYURoQ2IyMDBMMWRzUm1sb2VtaG5iamd4Ukd4a2IyZDZMMHN5VlhkTk5sTTJRMEl2VTBWNGEybFdabllyZW1KS01ISnFkbWM1TkVGc1pHcFZabFYzYTBrNVZrNU5ha1ZRTldVNGVXUkNNMjlNYkRabmJIQkRaVVkxWkdkbVUxZzBWVGw0TXpWdmFpOUpTV1F6VlVVdlpGQndZaTl4WjBkMmMydG1aR1Y2ZEcxVmRHVXZTMU50Y21sM1kyZFZWMWRsV0daVVlra3plbk5wYTNkYVltdHdiVkpaUzIxcVVHMW9kalJ5YkdsNlIwTkhkRGhRYmpod2NUaE5Na3RFWmk5UU0ydFdiM1F6WlRFNFVUMGlMQ0pOU1VsRlUycERRMEY2UzJkQmQwbENRV2RKVGtGbFR6QnRjVWRPYVhGdFFrcFhiRkYxUkVGT1FtZHJjV2hyYVVjNWR6QkNRVkZ6UmtGRVFrMU5VMEYzU0dkWlJGWlJVVXhGZUdSSVlrYzVhVmxYZUZSaFYyUjFTVVpLZG1JelVXZFJNRVZuVEZOQ1UwMXFSVlJOUWtWSFFURlZSVU5vVFV0U01uaDJXVzFHYzFVeWJHNWlha1ZVVFVKRlIwRXhWVVZCZUUxTFVqSjRkbGx0Um5OVk1teHVZbXBCWlVaM01IaE9la0V5VFZSVmQwMUVRWGRPUkVwaFJuY3dlVTFVUlhsTlZGVjNUVVJCZDA1RVNtRk5SVWw0UTNwQlNrSm5UbFpDUVZsVVFXeFdWRTFTTkhkSVFWbEVWbEZSUzBWNFZraGlNamx1WWtkVloxWklTakZqTTFGblZUSldlV1J0YkdwYVdFMTRSWHBCVWtKblRsWkNRVTFVUTJ0a1ZWVjVRa1JSVTBGNFZIcEZkMmRuUldsTlFUQkhRMU54UjFOSllqTkVVVVZDUVZGVlFVRTBTVUpFZDBGM1oyZEZTMEZ2U1VKQlVVUlJSMDA1UmpGSmRrNHdOWHByVVU4NUszUk9NWEJKVW5aS2VucDVUMVJJVnpWRWVrVmFhRVF5WlZCRGJuWlZRVEJSYXpJNFJtZEpRMlpMY1VNNVJXdHpRelJVTW1aWFFsbHJMMnBEWmtNelVqTldXazFrVXk5a1RqUmFTME5GVUZwU2NrRjZSSE5wUzFWRWVsSnliVUpDU2pWM2RXUm5lbTVrU1UxWlkweGxMMUpIUjBac05YbFBSRWxMWjJwRmRpOVRTa2d2VlV3clpFVmhiSFJPTVRGQ2JYTkxLMlZSYlUxR0t5dEJZM2hIVG1oeU5UbHhUUzg1YVd3M01Va3laRTQ0UmtkbVkyUmtkM1ZoWldvMFlsaG9jREJNWTFGQ1ltcDRUV05KTjBwUU1HRk5NMVEwU1N0RWMyRjRiVXRHYzJKcWVtRlVUa001ZFhwd1JteG5UMGxuTjNKU01qVjRiM2x1VlhoMk9IWk9iV3R4TjNwa1VFZElXR3Q0VjFrM2IwYzVhaXRLYTFKNVFrRkNhemRZY2twbWIzVmpRbHBGY1VaS1NsTlFhemRZUVRCTVMxY3dXVE42Tlc5Nk1rUXdZekYwU2t0M1NFRm5UVUpCUVVkcVoyZEZlazFKU1VKTWVrRlBRbWRPVmtoUk9FSkJaamhGUWtGTlEwRlpXWGRJVVZsRVZsSXdiRUpDV1hkR1FWbEpTM2RaUWtKUlZVaEJkMFZIUTBOelIwRlJWVVpDZDAxRFRVSkpSMEV4VldSRmQwVkNMM2RSU1UxQldVSkJaamhEUVZGQmQwaFJXVVJXVWpCUFFrSlpSVVpLYWxJclJ6UlJOamdyWWpkSFEyWkhTa0ZpYjA5ME9VTm1NSEpOUWpoSFFURlZaRWwzVVZsTlFtRkJSa3AyYVVJeFpHNUlRamRCWVdkaVpWZGlVMkZNWkM5alIxbFpkVTFFVlVkRFEzTkhRVkZWUmtKM1JVSkNRMnQzU25wQmJFSm5aM0pDWjBWR1FsRmpkMEZaV1ZwaFNGSXdZMFJ2ZGt3eU9XcGpNMEYxWTBkMGNFeHRaSFppTW1OMldqTk9lVTFxUVhsQ1owNVdTRkk0UlV0NlFYQk5RMlZuU21GQmFtaHBSbTlrU0ZKM1QyazRkbGt6U25OTWJrSnlZVk0xYm1JeU9XNU1NbVI2WTJwSmRsb3pUbmxOYVRWcVkyMTNkMUIzV1VSV1VqQm5Ra1JuZDA1cVFUQkNaMXB1WjFGM1FrRm5TWGRMYWtGdlFtZG5ja0puUlVaQ1VXTkRRVkpaWTJGSVVqQmpTRTAyVEhrNWQyRXlhM1ZhTWpsMlduazVlVnBZUW5aak1td3dZak5LTlV4NlFVNUNaMnR4YUd0cFJ6bDNNRUpCVVhOR1FVRlBRMEZSUlVGSGIwRXJUbTV1TnpoNU5uQlNhbVE1V0d4UlYwNWhOMGhVWjJsYUwzSXpVazVIYTIxVmJWbElVRkZ4TmxOamRHazVVRVZoYW5aM1VsUXlhVmRVU0ZGeU1ESm1aWE54VDNGQ1dUSkZWRlYzWjFwUksyeHNkRzlPUm5ab2MwODVkSFpDUTA5SllYcHdjM2RYUXpsaFNqbDRhblUwZEZkRVVVZzRUbFpWTmxsYVdpOVlkR1ZFVTBkVk9WbDZTbkZRYWxrNGNUTk5SSGh5ZW0xeFpYQkNRMlkxYnpodGR5OTNTalJoTWtjMmVIcFZjalpHWWpaVU9FMWpSRTh5TWxCTVVrdzJkVE5OTkZSNmN6TkJNazB4YWpaaWVXdEtXV2s0ZDFkSlVtUkJka3RNVjFwMUwyRjRRbFppZWxsdGNXMTNhMjAxZWt4VFJGYzFia2xCU21KRlRFTlJRMXAzVFVnMU5uUXlSSFp4YjJaNGN6WkNRbU5EUmtsYVZWTndlSFUyZURaMFpEQldOMU4yU2tORGIzTnBjbE50U1dGMGFpODVaRk5UVmtSUmFXSmxkRGh4THpkVlN6UjJORnBWVGpnd1lYUnVXbm94ZVdjOVBTSmRmUS5leUp1YjI1alpTSTZJbVoxUlZsb0szaFhVRkEzZUhCNVVUZzVhbGh3Y0ZGT05tMWlNV2RYWnpNM1JsQnZOM05VU2pFeFVFMDlJaXdpZEdsdFpYTjBZVzF3VFhNaU9qRTFORGcwT0RneU5UazRNamtzSW1Gd2ExQmhZMnRoWjJWT1lXMWxJam9pWTI5dExtZHZiMmRzWlM1aGJtUnliMmxrTG1kdGN5SXNJbUZ3YTBScFoyVnpkRk5vWVRJMU5pSTZJa0YyV0hGcE1FSnRiVXRKYm1KSVlqTXlaalI2VldoMmVqUmxjR3BwU25RM2EwdE5SMmhUZDNjeFJGVTlJaXdpWTNSelVISnZabWxzWlUxaGRHTm9JanAwY25WbExDSmhjR3REWlhKMGFXWnBZMkYwWlVScFoyVnpkRk5vWVRJMU5pSTZXeUk0VURGelZ6QkZVRXBqYzJ4M04xVjZVbk5wV0V3Mk5IY3JUelV3UldRclVrSkpRM1JoZVRGbk1qUk5QU0pkTENKaVlYTnBZMGx1ZEdWbmNtbDBlU0k2ZEhKMVpYMC5DQldQQ1FNaDBIdjhSTllZc05HTGVuci16RVEyY3o2Q25xalZhblZKOXV1b0d5WFpkc19mRTkwbFRjN0tpYVFMNExWSDl1TnNLWjdyN0xZSzRHTHhHekNqWklwZFlFZUIwdWxaWEN1bDdaVFI2MzZmODBWZmxkZ0dJdDRocWJ6S3dsd0EwNEZJN3ZpbDZjbkNJRHQ4SHVyTzVwRnJIdDVhUkpVcUxnOWhPT3VOaDVYS1JQS29aVTZyQlg5eVhxUmFtbl9SbWd6SkEwRGpqcXNaM3BlYUVvX2g5T0hJUHV3Q3FXZUdlZk5lRmoxVnBnaENpdW1lMXpPb2lwSmt3Tkx3dHdJamNDZ0VqYmc1OEF6ZHBPY01fLUtKYXBUeFJlYk9ZclM3dExTUlZfb2xjZG9PWGUtZ0ctVktCeTRUclJkdE9zNUdydTBqdlNyUGMwZXh6OHV2MkFoYXV0aERhdGFYxcrUbtuZYVMj5mIkvf6KvF1ZzC0gYwKd4+myQgSJCUO2RQAAAAC5P9lh8uZGL7EiggAiR954AEEBzzMqulVa/1QLDFjUXIyqQRLPaVXgI3BOTb4enX0uApu+Hm5Db+LoAxtNtPPXNw1qkIR6Isk+UABUzgvsAijDoqUBAgMmIAEhWCACJyweJ5aGUeFWycOhX/jCeAcTVjAxnbZnJmxj+aLWtyJYIAOY6jc/2y5iT60VYTtZaeBvsQIwgU/XR9Fax7xtatkY"}}');

        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $publicKeyCredential->getResponse());

        $credentialRepository = $this->prophesize(CredentialRepository::class);
        $credentialRepository->has(\Safe\base64_decode('Ac8zKrpVWv9UCwxY1FyMqkESz2lV4CNwTk2+Hp19LgKbvh5uQ2/i6AMbTbTz1zcNapCEeiLJPlAAVM4L7AIow6I=', true))->willReturn(false);

        $uri = $this->prophesize(UriInterface::class);
        $uri->getHost()->willReturn('webauthn.morselli.fr');
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getUri()->willReturn($uri->reveal());

        $client = new Client();
        $httpResponse = new Response();
        $httpResponse = $httpResponse->withHeader('content-type', 'application/json');
        $httpResponse->getBody()->write('{"isValidSignature":true}');
        $httpResponse->getBody()->rewind();
        $client->setDefaultResponse($httpResponse);

        $this->getAuthenticatorAttestationResponseValidator($credentialRepository->reveal(), $client)->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request->reveal()
        );

        $publicKeyCredentialDescriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor(['usb']);

        static::assertEquals(\Safe\base64_decode('Ac8zKrpVWv9UCwxY1FyMqkESz2lV4CNwTk2+Hp19LgKbvh5uQ2/i6AMbTbTz1zcNapCEeiLJPlAAVM4L7AIow6I=', true), Base64Url::decode($publicKeyCredential->getId()));
        static::assertEquals(\Safe\base64_decode('Ac8zKrpVWv9UCwxY1FyMqkESz2lV4CNwTk2+Hp19LgKbvh5uQ2/i6AMbTbTz1zcNapCEeiLJPlAAVM4L7AIow6I=', true), $publicKeyCredentialDescriptor->getId());
        static::assertEquals(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $publicKeyCredentialDescriptor->getType());
        static::assertEquals(['usb'], $publicKeyCredentialDescriptor->getTransports());

        /** @var AuthenticatorData $authenticatorData */
        $authenticatorData = $publicKeyCredential->getResponse()->getAttestationObject()->getAuthData();

        static::assertEquals(\Safe\hex2bin('cad46edb99615323e66224bdfe8abc5d59cc2d2063029de3e9b24204890943b6'), $authenticatorData->getRpIdHash());
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
    public function anAttestationWithTokenBindingCanBeVerified(): void
    {
        $publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity('My Application'),
            new PublicKeyCredentialUserEntity('test@foo.com', random_bytes(64), 'Test PublicKeyCredentialUserEntity'),
            \Safe\base64_decode('SkehMoAkGv+cqmuiEqpOgGhswj5oDa9kIPxgG1IihzkxPe4LNfP8bUyFiNn/MXBlqiOY6IpHFZl1XfIM07kRZw==', true),
            [
                new PublicKeyCredentialParameters('public-key', PublicKeyCredentialParameters::ALGORITHM_ES256),
            ],
            60000,
            [],
            new AuthenticatorSelectionCriteria(),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
            new AuthenticationExtensionsClientInputs()
        );

        $publicKeyCredential = $this->getPublicKeyCredentialLoader()->load('{"id":"-uZVS9-4JgjAYI49YhdzTgHmbn638-ZNSvC0UtHkWTVS-CtTjnaSbqtzdzijByOAvEAsh-TaQJAr43FRj-dYag","type":"public-key","rawId":"+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYag==","response":{"clientDataJSON":"ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5jcmVhdGUiLA0KCSJjaGFsbGVuZ2UiIDogIlNrZWhNb0FrR3YtY3FtdWlFcXBPZ0doc3dqNW9EYTlrSVB4Z0cxSWloemt4UGU0TE5mUDhiVXlGaU5uX01YQmxxaU9ZNklwSEZabDFYZklNMDdrUlp3IiwNCgkib3JpZ2luIiA6ICJodHRwczovL3dlYmF1dGhuLm1vcnNlbGxpLmZyIiwNCgkidG9rZW5CaW5kaW5nIiA6IA0KCXsNCgkJInN0YXR1cyIgOiAic3VwcG9ydGVkIg0KCX0NCn0=","attestationObject":"o2NmbXRmcGFja2VkaGF1dGhEYXRhWMTK1G7bmWFTI+ZiJL3+irxdWcwtIGMCnePpskIEiQlDtkUAAACS+KAR84wKTRWABhcRH57cfQBA+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYaqUBAgMmIAEhWCBghVX3//iILN98CBMBKcKrotdlzBdLaH/Hg88GTQV/HiJYIHJsHBPRfVuaLrsZcyiWxCSMZlJZkR7wZMg4a6oZ+zacZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgF/4vvqanyO+5+IHsw8GbSWh+qLHbejybS9K7mpIhR/ACIQCMImx8JpQjbCXrXxwJ1uUnwQcTXBVU3+luI56lJ+S9kGN4NWOBWQLCMIICvjCCAaagAwIBAgIEdIb9wjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk1NTAwMzg0MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJVd8633JH0xde/9nMTzGk6HjrrhgQlWYVD7OIsuX2Unv1dAmqWBpQ0KxS8YRFwKE1SKE1PIpOWacE5SO8BN6+2jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER+e3H0wDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMVxIgOaaUn44Zom9af0KqG9J655OhUVBVW+q0As6AIod3AH5bHb2aDYakeIyyBCnnGMHTJtuekbrHbXYXERIn4aKdkPSKlyGLsA/A+WEi+OAfXrNVfjhrh7iE6xzq0sg4/vVJoywe4eAJx0fS+Dl3axzTTpYl71Nc7p/NX6iCMmdik0pAuYJegBcTckE3AoYEg4K99AM/JaaKIblsbFh8+3LxnemeNf7UwOczaGGvjS6UzGVI0Odf9lKcPIwYhuTxM5CaNMXTZQ7xq4/yTfC3kPWtE4hFT34UJJflZBiLrxG4OsYxkHw/n5vKgmpspB3GfYuYTWhkDKiE8CYtyg87g=="}}');

        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $publicKeyCredential->getResponse());

        $credentialRepository = $this->prophesize(CredentialRepository::class);
        $credentialRepository->has(\Safe\base64_decode('+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYag==', true))->willReturn(false);

        $uri = $this->prophesize(UriInterface::class);
        $uri->getHost()->willReturn('webauthn.morselli.fr');
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getUri()->willReturn($uri->reveal());

        $this->getAuthenticatorAttestationResponseValidator($credentialRepository->reveal(), new Client())->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request->reveal()
        );

        $publicKeyCredentialDescriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor(['usb']);

        static::assertEquals(\Safe\base64_decode('+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYag==', true), Base64Url::decode($publicKeyCredential->getId()));
        static::assertEquals(\Safe\base64_decode('+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYag==', true), $publicKeyCredentialDescriptor->getId());
        static::assertEquals(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $publicKeyCredentialDescriptor->getType());
        static::assertEquals(['usb'], $publicKeyCredentialDescriptor->getTransports());

        /** @var AuthenticatorData $authenticatorData */
        $authenticatorData = $publicKeyCredential->getResponse()->getAttestationObject()->getAuthData();

        static::assertEquals(\Safe\hex2bin('cad46edb99615323e66224bdfe8abc5d59cc2d2063029de3e9b24204890943b6'), $authenticatorData->getRpIdHash());
        static::assertTrue($authenticatorData->isUserPresent());
        static::assertTrue($authenticatorData->isUserVerified());
        static::assertTrue($authenticatorData->hasAttestedCredentialData());
        static::assertEquals(0, $authenticatorData->getReservedForFutureUse1());
        static::assertEquals(0, $authenticatorData->getReservedForFutureUse2());
        static::assertEquals(146, $authenticatorData->getSignCount());
        static::assertInstanceOf(AttestedCredentialData::class, $authenticatorData->getAttestedCredentialData());
        static::assertFalse($authenticatorData->hasExtensions());
    }
}
