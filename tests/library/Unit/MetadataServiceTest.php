<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use function array_merge;
use function array_slice;
use Closure;
use Ergebnis\PHPUnit\SlowTestDetector\Attribute\MaximumDuration;
use InvalidArgumentException;
use function iterator_to_array;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use const JSON_THROW_ON_ERROR;
use const OPENSSL_KEYTYPE_EC;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
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
    #[DataProvider('rootCertificateEncodings')]
    #[MaximumDuration(5000)]
    public function fidoAllianceMetadataServiceLoadsABlobThatChainsToTheRootCertificate(string $rootCertificate): void
    {
        $service = self::createFidoAllianceMetadataService(self::genuineBlob(), $rootCertificate);

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
        $service = self::createFidoAllianceMetadataService(
            self::genuineBlob(),
            self::rootCertificate('MDS3ROOT.crt')
        );

        static::assertSame([], iterator_to_array($service->list(), false));
    }

    /**
     * The forged BLOB carries the genuine payload, reduced to its first entry whose attestation root certificate is
     * replaced with the certificate of the attacker, and is signed with the key of that certificate.
     *
     * @param Closure(string, list<string>): list<string> $certificateChain
     */
    #[Test]
    #[DataProvider('forgedCertificateChains')]
    #[MaximumDuration(5000)]
    public function fidoAllianceMetadataServiceIgnoresAForgedBlob(Closure $certificateChain): void
    {
        $service = self::createFidoAllianceMetadataService(
            self::forgeBlob($certificateChain),
            self::rootCertificate('FidoAllianceRootR3.crt')
        );

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
     * GlobalSign serves the root certificate as DER, the fixture is a PEM block.
     *
     * @return iterable<string, array{string}>
     */
    public static function rootCertificateEncodings(): iterable
    {
        yield 'PEM' => [self::rootCertificate('FidoAllianceRootR3.crt')];
        yield 'DER' => [PEM::fromString(self::rootCertificate('FidoAllianceRootR3.crt'))->data()];
    }

    /**
     * Each chain is given the certificate of the attacker and the genuine chain, both as "x5c" entries. In the last
     * two, the first entry holds the certificate of the attacker followed by the genuine signing certificate as a PEM
     * block: OpenSSL stops decoding base64 at the first dash and reads the former, pki-framework reads the latter.
     *
     * @return iterable<string, array{Closure(string, list<string>): list<string>}>
     */
    public static function forgedCertificateChains(): iterable
    {
        yield 'self-issued certificate' => [
            static fn (string $attacker, array $genuine): array => [$attacker],
        ];
        yield 'genuine signing certificate after carriage returns' => [
            static fn (string $attacker, array $genuine): array => array_merge(
                [$attacker . "\r-----BEGIN CERTIFICATE-----\r" . $genuine[0] . "\r-----END CERTIFICATE-----"],
                array_slice($genuine, 1)
            ),
        ];
        yield 'genuine signing certificate after line feeds' => [
            static fn (string $attacker, array $genuine): array => array_merge(
                [$attacker . "\n-----BEGIN CERTIFICATE-----\n" . $genuine[0] . "\n-----END CERTIFICATE-----"],
                array_slice($genuine, 1)
            ),
        ];
    }

    /**
     * The CRL distribution points of the chain answer 404: the validator tolerates an unreachable CRL by default.
     */
    private static function createFidoAllianceMetadataService(
        string $blob,
        string $rootCertificate
    ): FidoAllianceCompliantMetadataService {
        $responses = [
            self::BLOB_URI => $blob,
            self::ROOT_CERTIFICATE_URI => $rootCertificate,
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

    /**
     * @param Closure(string, list<string>): list<string> $certificateChain
     */
    private static function forgeBlob(Closure $certificateChain): string
    {
        $genuine = (new CompactSerializer())->unserialize(self::genuineBlob());
        /** @var list<string> $genuineCertificates */
        $genuineCertificates = $genuine->getSignature(0)
            ->getProtectedHeader()['x5c'];
        $payload = json_decode((string) $genuine->getPayload(), true, 512, JSON_THROW_ON_ERROR);

        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        $csr = openssl_csr_new([
            'commonName' => 'Forged metadata BLOB signer',
        ], $key);
        openssl_x509_export(openssl_csr_sign($csr, null, $key, 365), $attackerCertificate);
        openssl_pkey_export($key, $attackerPrivateKey);
        $attacker = base64_encode(PEM::fromString($attackerCertificate)->data());

        $entry = $payload['entries'][0];
        $entry['metadataStatement']['attestationRootCertificates'] = [$attacker];
        $payload['entries'] = [$entry];

        $jws = (new JWSBuilder(new AlgorithmManager([new ES256()])))
            ->create()
            ->withPayload(json_encode($payload, JSON_THROW_ON_ERROR))
            ->addSignature(JWKFactory::createFromKey($attackerPrivateKey), [
                'alg' => 'ES256',
                'x5c' => $certificateChain($attacker, $genuineCertificates),
            ])
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }

    private static function genuineBlob(): string
    {
        return trim(file_get_contents(__DIR__ . '/../../blob.jwt'));
    }

    private static function rootCertificate(string $filename): string
    {
        return file_get_contents(__DIR__ . '/../../certificates/' . $filename);
    }
}
