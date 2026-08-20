<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\Util;

use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Algorithm\Signature\EdDSA\EdDSA;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;
use Webauthn\Util\CoseSignatureFixer;

/**
 * The ASN.1 DER encoding of an ECDSA signature has a variable length: each INTEGER component is minimally encoded, so it
 * gets a leading zero byte when its high bit is set and loses its leading zero bytes otherwise.
 *
 * @internal
 *
 * @see https://w3c.github.io/webauthn/#sctn-signature-attestation-types
 */
final class CoseSignatureFixerTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string}>
     */
    public static function es256Signatures(): iterable
    {
        yield 'both components padded with a leading zero byte' => [
            '3046'
            . '022100' . str_repeat('ff', 32)
            . '02210080' . str_repeat('00', 31),
            str_repeat('ff', 32) . '80' . str_repeat('00', 31),
        ];

        yield 'both components exactly 32 bytes long' => [
            '3044'
            . '02207f' . str_repeat('ff', 31)
            . '022001' . str_repeat('00', 31),
            '7f' . str_repeat('ff', 31) . '01' . str_repeat('00', 31),
        ];

        yield 'specification example with a 33-byte and a 30-byte component' => [
            '3043'
            . '02210089909504e14f1e29dba8158fa7c387e888ffbe07d824bb2143205506ab159c3e'
            . '021e56554fb5819b12845e85be2f78371cf3cb95e387f451cb362b9478d183d2',
            '89909504e14f1e29dba8158fa7c387e888ffbe07d824bb2143205506ab159c3e'
            . '000056554fb5819b12845e85be2f78371cf3cb95e387f451cb362b9478d183d2',
        ];
    }

    #[Test]
    #[DataProvider('es256Signatures')]
    public function anEs256DerSignatureIsConvertedIntoItsRawForm(string $der, string $expected): void
    {
        // Given
        $signature = hex2bin($der);

        // When
        $fixed = CoseSignatureFixer::fix($signature, new ES256());

        // Then
        static::assertSame(64, strlen($fixed));
        static::assertSame($expected, bin2hex($fixed));
    }

    #[Test]
    public function anEs256RawSignatureIsLeftUntouched(): void
    {
        // Given
        $signature = hex2bin(str_repeat('ab', 64));

        // When
        $fixed = CoseSignatureFixer::fix($signature, new ES256());

        // Then
        static::assertSame($signature, $fixed);
    }

    #[Test]
    public function anEs384DerSignatureIsConvertedIntoItsRawForm(): void
    {
        // Given
        $signature = hex2bin(
            '3064'
            . '02307f' . str_repeat('ff', 47)
            . '023001' . str_repeat('00', 47)
        );

        // When
        $fixed = CoseSignatureFixer::fix($signature, new ES384());

        // Then
        static::assertSame(96, strlen($fixed));
        static::assertSame(
            '7f' . str_repeat('ff', 47) . '01' . str_repeat('00', 47),
            bin2hex($fixed)
        );
    }

    #[Test]
    public function anEs512DerSignatureUsingTheLongFormLengthIsConvertedIntoItsRawForm(): void
    {
        // Given
        $signature = hex2bin(
            '308188'
            . '024201' . str_repeat('00', 64) . 'ff'
            . '024201' . str_repeat('ff', 64) . '00'
        );

        // When
        $fixed = CoseSignatureFixer::fix($signature, new ES512());

        // Then
        static::assertSame(132, strlen($fixed));
        static::assertSame(
            '01' . str_repeat('00', 64) . 'ff01' . str_repeat('ff', 64) . '00',
            bin2hex($fixed)
        );
    }

    #[Test]
    public function anEs512DerSignatureWithAShorterComponentIsLeftPadded(): void
    {
        // Given
        $signature = hex2bin(
            '308186'
            . '0241' . str_repeat('11', 65)
            . '024201' . str_repeat('22', 65)
        );

        // When
        $fixed = CoseSignatureFixer::fix($signature, new ES512());

        // Then
        static::assertSame(132, strlen($fixed));
        static::assertSame(
            '00' . str_repeat('11', 65) . '01' . str_repeat('22', 65),
            bin2hex($fixed)
        );
    }

    #[Test]
    public function aSignatureOfANonEcdsaAlgorithmIsLeftUntouched(): void
    {
        // Given
        $signature = hex2bin(str_repeat('cd', 64));

        // When
        $fixed = CoseSignatureFixer::fix($signature, new EdDSA());

        // Then
        static::assertSame($signature, $fixed);
    }
}
