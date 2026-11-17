<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use const PHP_EOL;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\MetadataService\CertificateChain\CertificateToolbox;

/**
 * @internal
 */
final class CertificateChainValidatorTest extends TestCase
{
    /**
     * @use \Webauthn\CertificateToolbox::checkChain
     */
    #[Test]
    public function convertingDERCertificatesToPEMFormatSucceeds(): void
    {
        // Given
        $x5c = [
            file_get_contents(__DIR__ . '/../certificates/chain/1.der'),
            file_get_contents(__DIR__ . '/../certificates/chain/2.der'),
            file_get_contents(__DIR__ . '/../certificates/chain/3.der'),
            file_get_contents(__DIR__ . '/../certificates/chain/4.der'),
        ];
        $expected = [
            file_get_contents(__DIR__ . '/../certificates/chain/1.crt'),
            file_get_contents(__DIR__ . '/../certificates/chain/2.crt'),
            file_get_contents(__DIR__ . '/../certificates/chain/3.crt'),
            file_get_contents(__DIR__ . '/../certificates/chain/4.crt'),
        ];

        // When
        $certs = CertificateToolbox::convertAllDERToPEM($x5c);

        // Then
        static::assertSame($expected, $certs);
    }

    /**
     * An entry of "x5c" is always encoded from DER, even when it already looks like PEM text: the PEM parser and the
     * OpenSSL functions must never receive text chosen by the client.
     */
    #[Test]
    #[DataProvider('entriesThatLookLikePem')]
    public function entriesThatLookLikePemAreEncodedFromDerAnyway(string $entry): void
    {
        $pem = CertificateToolbox::convertDERToPEM($entry);

        static::assertSame(
            '-----BEGIN CERTIFICATE-----' . PHP_EOL . chunk_split(
                base64_encode($entry),
                64,
                PHP_EOL
            ) . '-----END CERTIFICATE-----' . PHP_EOL,
            $pem
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function entriesThatLookLikePem(): iterable
    {
        $certificate = (string) file_get_contents(__DIR__ . '/../certificates/chain/1.crt');

        yield 'a PEM certificate' => [$certificate];
        yield 'two PEM blocks, the first one with a space after its BEGIN line' => [
            str_replace('-----BEGIN CERTIFICATE-----', '-----BEGIN CERTIFICATE----- ', $certificate) . $certificate,
        ];
        yield 'a file path' => ['file:///-----BEGIN /../dev/null'];
    }
}
