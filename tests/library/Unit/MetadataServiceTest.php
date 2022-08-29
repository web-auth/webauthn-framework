<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use Http\Mock\Client;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Webauthn\MetadataService\Service\DistantResourceMetadataService;
use Webauthn\MetadataService\Service\FidoAllianceCompliantMetadataService;

/**
 * @internal
 */
final class MetadataServiceTest extends TestCase
{
    /**
     * @test
     */
    public function theMetadataServiceCanLoadUri(): void
    {
        $response = new Response(200, [], trim(file_get_contents(__DIR__ . '/../../blob.jwt')));
        $client = new Client();
        $client->addResponse($response);

        $service = new FidoAllianceCompliantMetadataService(new Psr17Factory(), $client, 'https://fidoalliance.co.nz');
        $aaguids = $service->list();
        foreach ($aaguids as $aaguid) {
            static::assertTrue($service->has($aaguid));
        }
    }

    /**
     * @test
     */
    public function aMetadataStatementFromAnUriCanBeRetrieved(): void
    {
        $response = new Response(200, [], trim(file_get_contents(__DIR__ . '/../../solo.json')));
        $client = new Client();
        $client->addResponse($response);

        $service = new DistantResourceMetadataService(
            new Psr17Factory(),
            $client,
            'https://raw.githubusercontent.com/solokeys/solo/2.1.0/metadata/Solo-FIDO2-CTAP2-Authenticator.json'
        );

        static::assertTrue($service->has('8876631b-d4a0-427f-5773-0ec71c9e0279'));
        $ms = $service->get('8876631b-d4a0-427f-5773-0ec71c9e0279');
        static::assertSame('8876631b-d4a0-427f-5773-0ec71c9e0279', $ms->getAAguid());
        static::assertSame('Solo Secp256R1 FIDO2 CTAP2 Authenticator', $ms->getDescription());
        static::assertSame([], $ms->getAlternativeDescriptions()->all());
        static::assertSame(3, $ms->getSchema());
    }
}
