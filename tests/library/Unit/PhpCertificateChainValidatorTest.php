<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use function array_slice;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Webauthn\Exception\CertificateChainException;
use Webauthn\MetadataService\CertificateChain\PhpCertificateChainValidator;

/**
 * The "fido-mds-r46" certificates are the "x5c" of the FIDO Alliance metadata BLOB served in November 2026: the
 * certificate of mds.fidoalliance.org, its issuing CA, then GlobalSign Root R46 cross-signed by GlobalSign Root CA -
 * R3. The FIDO Alliance names the self-signed GlobalSign Root R46 as the root certificate of that BLOB.
 *
 * @internal
 */
final class PhpCertificateChainValidatorTest extends TestCase
{
    private const CROSS_CERTIFICATE_CRL_URI = 'http://crl.globalsign.com/root-r3.crl';

    #[Test]
    #[DataProvider('fidoAllianceMetadataRootCertificates')]
    public function itValidatesTheFidoAllianceMetadataChainAgainstEitherGlobalSignRoot(string $rootCertificate): void
    {
        $this->expectNotToPerformAssertions();

        self::createValidator()->check(self::fidoAllianceMetadataChain(), [$rootCertificate]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function fidoAllianceMetadataRootCertificates(): iterable
    {
        yield 'GlobalSign Root R46, below the cross-certificate' => [self::fidoMdsCertificate('root-r46.pem')];
        yield 'GlobalSign Root CA - R3, through the cross-certificate' => [self::globalSignRootR3()];
    }

    #[Test]
    public function itRejectsAChainThatDoesNotReachTheTrustAnchor(): void
    {
        $chainWithoutTheCrossCertificate = array_slice(self::fidoAllianceMetadataChain(), 0, 2);

        $this->expectException(CertificateChainException::class);

        self::createValidator()->check($chainWithoutTheCrossCertificate, [self::globalSignRootR3()]);
    }

    #[Test]
    public function itRejectsAPathThatGoesThroughARevokedCertificate(): void
    {
        $validator = self::createValidator([
            self::CROSS_CERTIFICATE_CRL_URI => self::certificateRevocationList(
                self::fidoMdsCertificate('root-r46-cross-signed-by-r3.pem')
            ),
        ]);

        $this->expectException(CertificateChainException::class);
        $this->expectExceptionMessage('Revoked certificate found.');

        $validator->check(self::fidoAllianceMetadataChain(), [self::globalSignRootR3()]);
    }

    #[Test]
    public function itIgnoresARevokedCertificateAboveTheTrustAnchor(): void
    {
        $validator = self::createValidator([
            self::CROSS_CERTIFICATE_CRL_URI => self::certificateRevocationList(
                self::fidoMdsCertificate('root-r46-cross-signed-by-r3.pem')
            ),
        ]);

        $this->expectNotToPerformAssertions();

        $validator->check(self::fidoAllianceMetadataChain(), [self::fidoMdsCertificate('root-r46.pem')]);
    }

    #[Test]
    public function itValidatesCertificateChainWithSelfSignedRootCA(): void
    {
        $leafCert = file_get_contents(__DIR__ . '/../certificates/intermediate-ca/leaf.pem');
        $intermediateCert = file_get_contents(__DIR__ . '/../certificates/intermediate-ca/intermediate-ca.pem');
        $rootCert = file_get_contents(__DIR__ . '/../certificates/intermediate-ca/root-ca.pem');

        $httpClient = new MockHttpClient([new MockResponse('')]);

        $validator = PhpCertificateChainValidator::create($httpClient);

        // Test with root CA as trust anchor (self-signed certificate)
        // The untrusted chain includes leaf and intermediate
        // This should work with both old and new implementation
        $validator->check([$leafCert, $intermediateCert], [$rootCert]);

        // If we reach here, validation succeeded
        static::assertTrue(true);
    }

    #[Test]
    public function itAcceptsWhenLeafCertificateMatchesTrustAnchor(): void
    {
        $leafCert = file_get_contents(__DIR__ . '/../certificates/intermediate-ca/leaf.pem');

        $httpClient = new MockHttpClient([new MockResponse('')]);

        $validator = PhpCertificateChainValidator::create($httpClient);

        // When the leaf certificate is the same as the trust anchor, it should be accepted
        // This is a valid case mentioned in FIDO MDS spec:
        // "A trust anchor can be [...] even the attestation certificate itself"
        $validator->check([$leafCert], [$leafCert]);

        // If we reach here, validation succeeded
        static::assertTrue(true);
    }

    #[Test]
    public function itRejectsCertificateChainWithInvalidTrustAnchor(): void
    {
        $leafCert = file_get_contents(__DIR__ . '/../certificates/intermediate-ca/leaf.pem');
        $rootCert = file_get_contents(__DIR__ . '/../certificates/intermediate-ca/root-ca.pem');

        $httpClient = new MockHttpClient([new MockResponse('')]);

        $validator = PhpCertificateChainValidator::create($httpClient);

        // Leaf certificate cannot be verified with root CA directly (missing intermediate)
        $this->expectException(CertificateChainException::class);
        $validator->check([$leafCert], [$rootCert]);
    }

    /**
     * The certificates are all valid on the date of the clock. A CRL distribution point that is not given answers 404,
     * which the validator tolerates by default.
     *
     * @param array<string, string> $certificateRevocationLists The DER of the CRL served at each URI
     */
    private static function createValidator(array $certificateRevocationLists = []): PhpCertificateChainValidator
    {
        $client = new MockHttpClient(
            static fn (string $method, string $url): MockResponse => isset($certificateRevocationLists[$url])
                ? new MockResponse($certificateRevocationLists[$url])
                : new MockResponse('', [
                    'http_code' => 404,
                ])
        );

        return PhpCertificateChainValidator::create($client, new MockClock('2026-11-18T00:00:00+00:00'));
    }

    /**
     * @return list<string>
     */
    private static function fidoAllianceMetadataChain(): array
    {
        return [
            self::fidoMdsCertificate('leaf.pem'),
            self::fidoMdsCertificate('intermediate.pem'),
            self::fidoMdsCertificate('root-r46-cross-signed-by-r3.pem'),
        ];
    }

    private static function fidoMdsCertificate(string $filename): string
    {
        return (string) file_get_contents(__DIR__ . '/../certificates/fido-mds-r46/' . $filename);
    }

    private static function globalSignRootR3(): string
    {
        return (string) file_get_contents(__DIR__ . '/../../certificates/FidoAllianceRootR3.crt');
    }

    /**
     * A certificate revocation list that names the serial number of the given certificate.
     */
    private static function certificateRevocationList(string $revokedCertificate): string
    {
        $serialNumber = Certificate::fromPEM(PEM::fromString($revokedCertificate))
            ->tbsCertificate()
            ->serialNumber();

        return Sequence::create(
            Sequence::create(
                NullType::create(),
                NullType::create(),
                NullType::create(),
                NullType::create(),
                NullType::create(),
                Sequence::create(Sequence::create(Integer::create($serialNumber)))
            ),
            NullType::create(),
            NullType::create()
        )->toDER();
    }
}
