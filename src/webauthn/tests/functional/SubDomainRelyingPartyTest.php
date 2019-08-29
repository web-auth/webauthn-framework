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

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialSourceRepository;

/**
 * @group functional
 * @group Fido2
 */
class SubDomainRelyingPartyTest extends AbstractTestCase
{
    /**
     * @test
     */
    public function anAuthenticatorAttestationResponseWithSubdomainCanBeVerified(): void
    {
        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::createFromString('{"rp":{"name":"Webauthn Demo","id":"spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],"challenge":"xGQ2h2bK2tbn96eNutboG53FvUT30IV\/2ThoeKPu778=","attestation":"indirect","user":{"name":"fff","id":"MTY3YzljMjUtZThiYy00MzVmLTlhYmMtNDYxMWY5OTg3ODU4","displayName":"FFF"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":60000}');
        $publicKeyCredential = $this->getPublicKeyCredentialLoader()->load('{"id":"-cGSjQwC4UBTsh2Mw6guep2uTdLXOExla3QJrVpByOkEWJaOljo54PWOazmHtxBuV5DeysX7qjohoGYK2YibdA","type":"public-key","rawId":"+cGSjQwC4UBTsh2Mw6guep2uTdLXOExla3QJrVpByOkEWJaOljo54PWOazmHtxBuV5DeysX7qjohoGYK2YibdA==","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJ4R1EyaDJiSzJ0Ym45NmVOdXRib0c1M0Z2VVQzMElWXzJUaG9lS1B1Nzc4Iiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5zcG9ta3ktbGFicy5jb20iLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=","attestationObject":"o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhALotmA9bjE8DC5afT4C6QJHwB2TDCgh+/DSpIuxt1Z2dAiBzVRmktx9Ur1sjxZJvjhAnzZCRDicD/h2dyd8a+MkVGWN4NWOBWQLCMIICvjCCAaagAwIBAgIEdIb9wjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk1NTAwMzg0MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJVd8633JH0xde/9nMTzGk6HjrrhgQlWYVD7OIsuX2Unv1dAmqWBpQ0KxS8YRFwKE1SKE1PIpOWacE5SO8BN6+2jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER+e3H0wDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMVxIgOaaUn44Zom9af0KqG9J655OhUVBVW+q0As6AIod3AH5bHb2aDYakeIyyBCnnGMHTJtuekbrHbXYXERIn4aKdkPSKlyGLsA/A+WEi+OAfXrNVfjhrh7iE6xzq0sg4/vVJoywe4eAJx0fS+Dl3axzTTpYl71Nc7p/NX6iCMmdik0pAuYJegBcTckE3AoYEg4K99AM/JaaKIblsbFh8+3LxnemeNf7UwOczaGGvjS6UzGVI0Odf9lKcPIwYhuTxM5CaNMXTZQ7xq4/yTfC3kPWtE4hFT34UJJflZBiLrxG4OsYxkHw/n5vKgmpspB3GfYuYTWhkDKiE8CYtyg87mhhdXRoRGF0YVjEzJVnqxWDxWv1dKGpGXUmkUO/MGMFSRae4FA9zhbiR3VBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQPnBko0MAuFAU7IdjMOoLnqdrk3S1zhMZWt0Ca1aQcjpBFiWjpY6OeD1jms5h7cQbleQ3srF+6o6IaBmCtmIm3SlAQIDJiABIVggZ9kAaP2QIzTF401zK9+GnJ9t5P5nZMd+7Uq2dj9zrDciWCAYPJnCkmc15U8txqQB+CdSKUhpVrhITkmBPycz6nzp8g=="}}');

        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $publicKeyCredential->getResponse());

        $credentialRepository = $this->prophesize(PublicKeyCredentialSourceRepository::class);
        $credentialRepository->findOneByCredentialId(base64_decode('+cGSjQwC4UBTsh2Mw6guep2uTdLXOExla3QJrVpByOkEWJaOljo54PWOazmHtxBuV5DeysX7qjohoGYK2YibdA==', true))->willReturn(null);

        $uri = $this->prophesize(UriInterface::class);
        $uri->getHost()->willReturn('localhost');
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getUri()->willReturn($uri->reveal());

        $this->getAuthenticatorAttestationResponseValidator($credentialRepository->reveal())->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request->reveal()
        );
    }
}
