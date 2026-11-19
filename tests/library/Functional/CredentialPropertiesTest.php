<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Webauthn\AuthenticationExtensions\CredentialPropertiesOutput;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\Exception\AuthenticationExtensionException;
use Webauthn\PublicKeyCredential;
use Webauthn\Tests\AbstractTestCase;

/**
 * `credProps` is a client extension result: it never appears in the authenticator data. The deserialized credential
 * exposes it through the client extension results of its response.
 *
 * @see https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension
 *
 * @internal
 */
final class CredentialPropertiesTest extends AbstractTestCase
{
    private const NULL_AAGUID = '00000000-0000-0000-0000-000000000000';

    #[Test]
    public function theCredentialPropertiesAreReadFromTheClientExtensionResults(): void
    {
        $response = $this->registration([
            'credProps' => [
                'rk' => true,
                'authenticatorDisplayName' => 'My phone',
            ],
        ]);

        static::assertNull($response->attestationObject->authData->extensions);
        static::assertNotNull($response->clientExtensionResults);
        $credProps = CredentialPropertiesOutput::fromExtensions($response->clientExtensionResults);
        static::assertNotNull($credProps);
        static::assertTrue($credProps->rk);
        static::assertSame('My phone', $credProps->authenticatorDisplayName);
    }

    #[Test]
    public function aMalformedCredentialPropertiesOutputIsRejectedWhenRead(): void
    {
        $response = $this->registration([
            'credProps' => [
                'rk' => 'yes',
            ],
        ]);
        static::assertNotNull($response->clientExtensionResults);

        $this->expectException(AuthenticationExtensionException::class);
        $this->expectExceptionMessage('The "credProps.rk" output must be a boolean.');

        CredentialPropertiesOutput::fromExtensions($response->clientExtensionResults);
    }

    /**
     * @param array<string, mixed> $clientExtensionResults
     */
    private function registration(array $clientExtensionResults): AuthenticatorAttestationResponse
    {
        $data = json_decode(
            SoftwareAuthenticator::packed('a challenge', self::NULL_AAGUID),
            true,
            512,
            JSON_THROW_ON_ERROR
        );
        $data['clientExtensionResults'] = $clientExtensionResults;

        $credential = $this->getSerializer()
            ->deserialize(json_encode($data, JSON_THROW_ON_ERROR), PublicKeyCredential::class, 'json');
        static::assertInstanceOf(PublicKeyCredential::class, $credential);
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $credential->response);

        return $credential->response;
    }
}
