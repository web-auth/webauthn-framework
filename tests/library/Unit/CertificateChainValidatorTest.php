<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

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
    public function anCertificateChainValidatorCanBeCreatedAndValueAccessed(): void
    {
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

        $certs = CertificateToolbox::convertAllDERToPEM($x5c);
        static::assertSame($expected, $certs);
    }
}
