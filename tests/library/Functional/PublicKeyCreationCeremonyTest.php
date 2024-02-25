<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\Tests\AbstractTestCase;

/**
 * @internal
 */
final class PublicKeyCreationCeremonyTest extends AbstractTestCase
{
    #[Test]
    #[DataProvider('getPublicKeyCredentialCreationOptions')]
    public function theCeremonySucceeded(
        string $options,
        string $response,
        string $keyId,
        string $type,
        string $host
    ): void {
        $publicKeyCredentialCreationOptions = $this->getSerializer()
            ->deserialize($options, PublicKeyCredentialCreationOptions::class, 'json');
        $publicKeyCredential = $this->getSerializer()
            ->deserialize($response, PublicKeyCredential::class, 'json');
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $publicKeyCredential->response);
        $source = $this->getAuthenticatorAttestationResponseValidator()
            ->check($publicKeyCredential->response, $publicKeyCredentialCreationOptions, $host);

        static::assertSame(hex2bin($keyId), $source->publicKeyCredentialId);
        static::assertSame($type, $source->attestationType);
    }

    public static function getPublicKeyCredentialCreationOptions(): iterable
    {
        yield 'anAuthenticatorAttestationResponseWithSubdomainCanBeVerified' => [
            '{"rp":{"name":"Webauthn Demo","id":"spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],"challenge":"xGQ2h2bK2tbn96eNutboG53FvUT30IV_2ThoeKPu778","attestation":"indirect","user":{"name":"fff","id":"MTY3YzljMjUtZThiYy00MzVmLTlhYmMtNDYxMWY5OTg3ODU4","displayName":"FFF"},"authenticatorSelection":{"userVerification":"preferred"},"timeout":60000}',
            '{"id":"-cGSjQwC4UBTsh2Mw6guep2uTdLXOExla3QJrVpByOkEWJaOljo54PWOazmHtxBuV5DeysX7qjohoGYK2YibdA","type":"public-key","rawId":"+cGSjQwC4UBTsh2Mw6guep2uTdLXOExla3QJrVpByOkEWJaOljo54PWOazmHtxBuV5DeysX7qjohoGYK2YibdA==","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJ4R1EyaDJiSzJ0Ym45NmVOdXRib0c1M0Z2VVQzMElWXzJUaG9lS1B1Nzc4Iiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5zcG9ta3ktbGFicy5jb20iLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0","attestationObject":"o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhALotmA9bjE8DC5afT4C6QJHwB2TDCgh+/DSpIuxt1Z2dAiBzVRmktx9Ur1sjxZJvjhAnzZCRDicD/h2dyd8a+MkVGWN4NWOBWQLCMIICvjCCAaagAwIBAgIEdIb9wjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk1NTAwMzg0MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJVd8633JH0xde/9nMTzGk6HjrrhgQlWYVD7OIsuX2Unv1dAmqWBpQ0KxS8YRFwKE1SKE1PIpOWacE5SO8BN6+2jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER+e3H0wDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMVxIgOaaUn44Zom9af0KqG9J655OhUVBVW+q0As6AIod3AH5bHb2aDYakeIyyBCnnGMHTJtuekbrHbXYXERIn4aKdkPSKlyGLsA/A+WEi+OAfXrNVfjhrh7iE6xzq0sg4/vVJoywe4eAJx0fS+Dl3axzTTpYl71Nc7p/NX6iCMmdik0pAuYJegBcTckE3AoYEg4K99AM/JaaKIblsbFh8+3LxnemeNf7UwOczaGGvjS6UzGVI0Odf9lKcPIwYhuTxM5CaNMXTZQ7xq4/yTfC3kPWtE4hFT34UJJflZBiLrxG4OsYxkHw/n5vKgmpspB3GfYuYTWhkDKiE8CYtyg87mhhdXRoRGF0YVjEzJVnqxWDxWv1dKGpGXUmkUO/MGMFSRae4FA9zhbiR3VBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQPnBko0MAuFAU7IdjMOoLnqdrk3S1zhMZWt0Ca1aQcjpBFiWjpY6OeD1jms5h7cQbleQ3srF+6o6IaBmCtmIm3SlAQIDJiABIVggZ9kAaP2QIzTF401zK9+GnJ9t5P5nZMd+7Uq2dj9zrDciWCAYPJnCkmc15U8txqQB+CdSKUhpVrhITkmBPycz6nzp8g=="}}',
            'f9c1928d0c02e14053b21d8cc3a82e7a9dae4dd2d7384c656b7409ad5a41c8e90458968e963a39e0f58e6b3987b7106e5790decac5fbaa3a21a0660ad9889b74',
            'basic',
            'spomky-labs.com',
        ];
        yield 'wrongEdDSAlgorithmIsFixed' => [
            '{"rp": {"name": "Tuleap", "id": "tuleap-web.tuleap-aio-dev.docker"}, "user": {"name": "admin", "id": "MTAx", "displayName": "Site Administrator"}, "challenge": "oq1vpg74u-TmqW3Dv2LwU_jH00NQf65OqpMhrvr7yPY", "pubKeyCredParams": [{"type": "public-key", "alg": -8}, {"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}], "attestation": "none"}',
            '{"clientExtensionResults": {}, "id": "ma2Y7hbtrzJtoDR4N2PkazhnrO6_58gZ8mO8epx-6aCnR9Jtio8Ge1w0_msV7HniYmLIH9yxOW8Yu_9ze_y8oj-MehAozj1jFTsjlQUEc_dxdzG5uFJTn6_RnzhulEWCcZZwcvlNTYne99MpWAD31c-4IuEr-eRRV1DWSANcax0", "rawId": "ma2Y7hbtrzJtoDR4N2PkazhnrO6_58gZ8mO8epx-6aCnR9Jtio8Ge1w0_msV7HniYmLIH9yxOW8Yu_9ze_y8oj-MehAozj1jFTsjlQUEc_dxdzG5uFJTn6_RnzhulEWCcZZwcvlNTYne99MpWAD31c-4IuEr-eRRV1DWSANcax0", "response": {"attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBCRawLfvD1MyjfrwvZRZlmxIhDbnhAYq58TqWkGOOpv2oRQAAAAIvwFefgRNH6rEWu1qNuSAqAICZrZjuFu2vMm2gNHg3Y-RrOGes7r_nyBnyY7x6nH7poKdH0m2KjwZ7XDT-axXseeJiYsgf3LE5bxi7_3N7_LyiP4x6ECjOPWMVOyOVBQRz93F3Mbm4UlOfr9GfOG6URYJxlnBy-U1Nid730ylYAPfVz7gi4Sv55FFXUNZIA1xrHaMBY09LUAMnIGdFZDI1NTE5IZggCBjXGDcYzBgpGFwYlBgcGJYYTxjdGOYY8BjyGL4YPxg7GEgYfBh_GCIYKxhgChgmGIQYkhhQGH0Y1hjoGIk", "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJvcTF2cGc3NHUtVG1xVzNEdjJMd1VfakgwME5RZjY1T3FwTWhydnI3eVBZIiwib3JpZ2luIjoiaHR0cHM6Ly90dWxlYXAtd2ViLnR1bGVhcC1haW8tZGV2LmRvY2tlciIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ"}, "type": "public-key"}',
            '99ad98ee16edaf326da034783763e46b3867aceebfe7c819f263bc7a9c7ee9a0a747d26d8a8f067b5c34fe6b15ec79e26262c81fdcb1396f18bbff737bfcbca23f8c7a1028ce3d63153b2395050473f7717731b9b852539fafd19f386e94458271967072f94d4d89def7d3295800f7d5cfb822e12bf9e4515750d648035c6b1d',
            'none',
            'tuleap-web.tuleap-aio-dev.docker',
        ];
    }
}
