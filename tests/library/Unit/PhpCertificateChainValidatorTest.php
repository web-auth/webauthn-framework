<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Webauthn\Exception\CertificateChainException;
use Webauthn\MetadataService\CertificateChain\PhpCertificateChainValidator;

/**
 * @internal
 */
final class PhpCertificateChainValidatorTest extends TestCase
{
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
}
