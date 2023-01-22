<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

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
        $credentialRepository = new MemoryPublicKeyCredentialSourceRepository();
        $pkOptions = PublicKeyCredentialCreationOptions::createFromString($options);
        //When
        $publicKeyCredential = $this->getPublicKeyCredentialLoader()
            ->load($response);
        $this->getAuthenticatorAttestationResponseValidator($credentialRepository)
            ->check($publicKeyCredential->getResponse(), $pkOptions, 'localhost');
    }

    /**
     * @return array<int, array<int, string>>
     */
    public function dataInvalidAttestation(): array
    {
        return [];
    }
}
