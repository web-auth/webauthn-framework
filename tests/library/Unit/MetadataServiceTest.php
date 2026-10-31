<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use Ergebnis\PHPUnit\SlowTestDetector\Attribute\MaximumDuration;
use InvalidArgumentException;
use function iterator_to_array;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Webauthn\MetadataService\CertificateChain\PhpCertificateChainValidator;
use Webauthn\MetadataService\Service\DistantResourceMetadataService;
use Webauthn\MetadataService\Service\FidoAllianceCompliantMetadataService;

/**
 * The BLOB of the fixtures is the one of the FIDO Alliance Metadata Service, signed with a certificate of
 * mds.fidoalliance.org valid from June 2023 to July 2024 and chained to GlobalSign Root CA - R3. The tests that load
 * it are slow because it is a large file.
 *
 * @internal
 */
final class MetadataServiceTest extends TestCase
{
    private const BLOB_URI = 'https://mds.fidoalliance.org/';

    private const ROOT_CERTIFICATE_URI = 'https://secure.globalsign.com/cacert/root-r3.crt';

    #[Test]
    #[MaximumDuration(5000)]
    public function fidoAllianceMetadataServiceLoadsABlobThatChainsToTheRootCertificate(): void
    {
        $service = $this->createFidoAllianceMetadataService(__DIR__ . '/../../certificates/FidoAllianceRootR3.crt');

        $aaguids = iterator_to_array($service->list(), false);

        static::assertNotSame([], $aaguids);
        foreach ($aaguids as $aaguid) {
            static::assertTrue($service->has($aaguid));
        }
    }

    #[Test]
    #[MaximumDuration(5000)]
    public function fidoAllianceMetadataServiceIgnoresABlobThatDoesNotChainToTheRootCertificate(): void
    {
        $service = $this->createFidoAllianceMetadataService(__DIR__ . '/../../certificates/MDS3ROOT.crt');

        static::assertSame([], iterator_to_array($service->list(), false));
    }

    #[Test]
    public function fidoAllianceMetadataServiceRequiresACertificateChainValidator(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('A certificate chain validator is required');

        FidoAllianceCompliantMetadataService::create(
            new MockHttpClient(),
            self::BLOB_URI,
            [],
            null,
            self::ROOT_CERTIFICATE_URI
        );
    }

    #[Test]
    public function fidoAllianceMetadataServiceRequiresARootCertificateUri(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The root certificate URI is required');

        FidoAllianceCompliantMetadataService::create(
            new MockHttpClient(),
            self::BLOB_URI,
            [],
            PhpCertificateChainValidator::create(new MockHttpClient())
        );
    }

    #[Test]
    public function distantMetadataServiceCanRetrieveMetadataStatementFromUri(): void
    {
        // Given
        $response = new MockResponse(trim(file_get_contents(__DIR__ . '/../../solo.json')));
        $client = new MockHttpClient();
        $client->setResponseFactory($response);

        $service = DistantResourceMetadataService::create(
            $client,
            'https://raw.githubusercontent.com/solokeys/solo/2.1.0/metadata/Solo-FIDO2-CTAP2-Authenticator.json'
        );

        // When
        $hasMetadata = $service->has('8876631b-d4a0-427f-5773-0ec71c9e0279');
        $ms = $service->get('8876631b-d4a0-427f-5773-0ec71c9e0279');

        // Then
        static::assertTrue($hasMetadata);
        static::assertSame('8876631b-d4a0-427f-5773-0ec71c9e0279', $ms->aaguid);
        static::assertSame('Solo Secp256R1 FIDO2 CTAP2 Authenticator', $ms->description);
        static::assertSame([], $ms->alternativeDescriptions->descriptions);
        static::assertSame(3, $ms->schema);
    }

    /**
     * The CRL distribution points of the chain answer 404: the validator tolerates an unreachable CRL by default.
     */
    private function createFidoAllianceMetadataService(
        string $rootCertificatePath
    ): FidoAllianceCompliantMetadataService {
        $responses = [
            self::BLOB_URI => trim(file_get_contents(__DIR__ . '/../../blob.jwt')),
            self::ROOT_CERTIFICATE_URI => file_get_contents($rootCertificatePath),
        ];
        $client = new MockHttpClient(
            static fn (string $method, string $url): MockResponse => isset($responses[$url])
                ? new MockResponse($responses[$url])
                : new MockResponse('', [
                    'http_code' => 404,
                ])
        );

        return FidoAllianceCompliantMetadataService::create(
            $client,
            self::BLOB_URI,
            [],
            PhpCertificateChainValidator::create($client, new MockClock('2024-01-01T00:00:00+00:00')),
            self::ROOT_CERTIFICATE_URI
        );
    }
}
