<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\SecurePaymentConfirmation;

use Cose\Algorithms;
use Cose\Key\Ec2Key;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\Exception\InvalidDataException;
use Webauthn\SecurePaymentConfirmation\BrowserBoundPublicKey;

/**
 * @internal
 */
final class BrowserBoundPublicKeyTest extends TestCase
{
    /**
     * The `browserBoundPublicKey` of a Chrome payment: an ES256 COSE_Key, encoded in base64url.
     */
    private const CHROME_BROWSER_BOUND_PUBLIC_KEY = 'pQECAyYgASFYIOUsBC35x2TSfRGkSeKL_uHMiWe_ptKFneJmAnIsaO4RIlggQWPJ1LAnV7OxxGq9ovhnXOqIQB7-7X6cduprsGgqEHk';

    #[Test]
    public function canBeCreated(): void
    {
        $key = BrowserBoundPublicKey::create("\xa5\x01\x02");

        static::assertSame("\xa5\x01\x02", $key->publicKey);
    }

    #[Test]
    public function emptyPublicKeyIsRejected(): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('The browser-bound public key must not be empty.');

        new BrowserBoundPublicKey('');
    }

    #[Test]
    public function theAlgorithmOfAChromeKeyIsEs256(): void
    {
        $key = BrowserBoundPublicKey::create(Base64UrlSafe::decodeNoPadding(self::CHROME_BROWSER_BOUND_PUBLIC_KEY));

        static::assertSame(Algorithms::COSE_ALGORITHM_ES256, $key->algorithm());
    }

    #[Test]
    public function theCoseKeyOfAChromeKeyIsAnEs256Ec2Key(): void
    {
        $coseKey = BrowserBoundPublicKey::create(
            Base64UrlSafe::decodeNoPadding(self::CHROME_BROWSER_BOUND_PUBLIC_KEY)
        )->coseKey();

        static::assertInstanceOf(Ec2Key::class, $coseKey);
        static::assertSame(Ec2Key::CURVE_P256, $coseKey->curve());
        static::assertSame(Algorithms::COSE_ALGORITHM_ES256, $coseKey->alg());
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideAlgorithms(): iterable
    {
        yield 'EC2, ES256' => ['a201020326', -7];
        yield 'RSA, RS256' => ['a2010303390100', -257];
        yield 'OKP, EdDSA' => ['a201010327', -8];
        yield 'EC2, ESP256' => ['a201020328', -9];
        yield 'alg before kty' => ['a203260102', -7];
        yield 'no kty' => ['a10326', -7];
        yield 'positive identifier' => ['a201020301', 1];
    }

    #[Test]
    #[DataProvider('provideAlgorithms')]
    public function theAlgorithmIsTheAlgMemberOfTheCoseKey(string $hex, int $expected): void
    {
        static::assertSame($expected, BrowserBoundPublicKey::create((string) hex2bin($hex))->algorithm());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideKeysWithoutIntegerAlgorithm(): iterable
    {
        yield 'empty map' => ['a0', 'no integer "alg" member'];
        yield 'no alg' => ['a10102', 'no integer "alg" member'];
        yield 'alg as a numeric text string' => ['a2010203622d37', 'no integer "alg" member'];
        yield 'alg as a text string' => ['a2010203654553323536', 'no integer "alg" member'];
        yield 'alg as a byte string' => ['a20102034107', 'no integer "alg" member'];
        yield 'alg beyond the integer range' => ['a20102031bffffffffffffffff', 'no integer "alg" member'];
        yield 'negative alg beyond the integer range' => [
            'a20102033bffffffffffffffff',
            'no integer "alg" member',
        ];
        yield 'alg under a text label' => ['a20102613326', 'no integer "alg" member'];
        yield 'a CBOR array' => ['820102', 'expected a CBOR map'];
        yield 'a CBOR text string' => ['626869', 'expected a CBOR map'];
        yield 'extra bytes' => ['a20102032600', 'extra bytes after the COSE key'];
        yield 'truncated map' => ['a2010203', 'the COSE_Key cannot be decoded'];
    }

    #[Test]
    #[DataProvider('provideKeysWithoutIntegerAlgorithm')]
    public function theAlgorithmOfAKeyWithoutIntegerAlgIsRefused(string $hex, string $message): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage($message);

        BrowserBoundPublicKey::create((string) hex2bin($hex))->algorithm();
    }

    #[Test]
    #[DataProvider('provideKeysWithoutIntegerAlgorithm')]
    public function theCoseKeyOfAKeyWithoutIntegerAlgIsRefused(string $hex, string $message): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage($message);

        BrowserBoundPublicKey::create((string) hex2bin($hex))->coseKey();
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidCoseKeys(): iterable
    {
        yield 'no kty' => ['a10326'];
        yield 'EC2 key without curve nor coordinates' => ['a201020326'];
    }

    #[Test]
    #[DataProvider('provideInvalidCoseKeys')]
    public function anInvalidCoseKeyIsRefused(string $hex): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('Invalid browserBoundPublicKey: the COSE_Key is invalid.');

        BrowserBoundPublicKey::create((string) hex2bin($hex))->coseKey();
    }
}
