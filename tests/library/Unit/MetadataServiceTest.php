<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Webauthn\MetadataService\Service\DistantResourceMetadataService;
use Webauthn\MetadataService\Service\FidoAllianceCompliantMetadataService;

/**
 * @internal
 */
final class MetadataServiceTest extends TestCase
{
    #[Test]
    public function theMetadataServiceCanLoadUri(): void
    {
        //Given
        $response = new MockResponse(trim(file_get_contents(__DIR__ . '/../../blob.jwt')));
        $client = new MockHttpClient();
        $client->setResponseFactory($response);

        $service = FidoAllianceCompliantMetadataService::create($client, 'https://fidoalliance.co.nz');
        $aaguids = $service->list();
        foreach ($aaguids as $aaguid) {
            static::assertTrue($service->has($aaguid));
        }
    }

    #[Test]
    public function aMetadataStatementFromAnUriCanBeRetrieved(): void
    {
        //Given
        $response = new MockResponse(trim(file_get_contents(__DIR__ . '/../../solo.json')));
        $client = new MockHttpClient();
        $client->setResponseFactory($response);

        //When
        $service = DistantResourceMetadataService::create(
            $client,
            'https://raw.githubusercontent.com/solokeys/solo/2.1.0/metadata/Solo-FIDO2-CTAP2-Authenticator.json'
        );

        //Then
        static::assertTrue($service->has('8876631b-d4a0-427f-5773-0ec71c9e0279'));
        $ms = $service->get('8876631b-d4a0-427f-5773-0ec71c9e0279');
        static::assertSame('8876631b-d4a0-427f-5773-0ec71c9e0279', $ms->aaguid);
        static::assertSame('Solo Secp256R1 FIDO2 CTAP2 Authenticator', $ms->description);
        static::assertSame([], $ms->alternativeDescriptions->descriptions);
        static::assertSame(3, $ms->schema);
    }
}
