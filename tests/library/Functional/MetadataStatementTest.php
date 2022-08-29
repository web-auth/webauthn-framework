<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use Nyholm\Psr7\ServerRequest;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\Tests\MemoryPublicKeyCredentialSourceRepository;

/**
 * @internal
 */
final class MetadataStatementTest extends AbstractTestCase
{
    /**
     * @test
     * @dataProvider dataInvalidAttestation
     */
    public function theAttestationCannotBeVerified(string $options, string $response, string $message): void
    {
        //Then
        $this->expectExceptionMessage($message);

        //Given
        $request = new ServerRequest('POST', 'https://localhost/');
        $credentialRepository = new MemoryPublicKeyCredentialSourceRepository();
        $pkOptions = PublicKeyCredentialCreationOptions::createFromString($options);

        //When
        $publicKeyCredential = $this->getPublicKeyCredentialLoader()
            ->load($response);
        $this->getAuthenticatorAttestationResponseValidator($credentialRepository)
            ->check($publicKeyCredential->getResponse(), $pkOptions, $request);
    }

    /**
     * @return array<int, array<int, string>>
     */
    public function dataInvalidAttestation(): array
    {
        return [];
    }
}
