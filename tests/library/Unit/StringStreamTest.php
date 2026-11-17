<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use ParagonIE\ConstantTime\Base64UrlSafe;
use const PHP_INT_MAX;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use function str_repeat;
use Webauthn\Exception\InvalidDataException;
use Webauthn\PublicKeyCredential;
use Webauthn\StringStream;
use Webauthn\Tests\AbstractTestCase;

/**
 * The length given to StringStream::read() often comes from a CBOR head of the data being decoded. A read past the
 * end must end in an InvalidDataException before any buffer of that length is allocated. PHP cannot allocate
 * PHP_INT_MAX bytes whatever the memory_limit, so a regression shows up as an "Allowed memory size exhausted" fatal
 * error that stops the test suite.
 *
 * @internal
 */
final class StringStreamTest extends AbstractTestCase
{
    /**
     * @return iterable<string, array{int, string}>
     */
    public static function lengthsPastTheEnd(): iterable
    {
        yield 'one byte past the end' => [4, 'Out of range. Expected: 4, read: 3.'];
        yield 'the 4 GiB declared by the CBOR head 5b 00 00 00 01 00 00 00 00' => [
            4_294_967_296,
            'Out of range. Expected: 4294967296, read: 3.',
        ];
        yield 'the largest length a CBOR head can declare' => [
            PHP_INT_MAX,
            sprintf('Out of range. Expected: %d, read: 3.', PHP_INT_MAX),
        ];
    }

    #[Test]
    #[DataProvider('lengthsPastTheEnd')]
    public function aReadPastTheEndIsRejectedBeforeAnyBufferIsAllocated(int $length, string $expectedMessage): void
    {
        $stream = new StringStream('abc');

        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage($expectedMessage);

        $stream->read($length);
    }

    #[Test]
    public function theBytesAlreadyReadAreNoLongerAvailable(): void
    {
        $stream = new StringStream('abc');
        static::assertSame('ab', $stream->read(2));

        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('Out of range. Expected: 2, read: 1.');

        $stream->read(2);
    }

    #[Test]
    public function theBytesAreReadInOrderUpToTheEnd(): void
    {
        $stream = new StringStream('abc');

        static::assertSame('', $stream->read(0));
        static::assertSame('a', $stream->read(1));
        static::assertFalse($stream->isEOF());
        static::assertSame('bc', $stream->read(2));
        static::assertTrue($stream->isEOF());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function credentialsDeclaringAHugeByteString(): iterable
    {
        $hugeByteString = "\x5b\x7f\xff\xff\xff\xff\xff\xff\xff" . 'abcde';

        yield 'sign-in, extensions of the authenticator data' => [
            self::credential('webauthn.get', sprintf(
                '"authenticatorData":"%s","signature":"AAAA","userHandle":null',
                Base64UrlSafe::encodeUnpadded(str_repeat("\0", 32) . "\x85\x00\x00\x00\x01" . $hugeByteString)
            )),
        ];
        yield 'registration, attestation object' => [
            self::credential('webauthn.create', sprintf(
                '"attestationObject":"%s"',
                Base64UrlSafe::encodeUnpadded($hugeByteString)
            )),
        ];
    }

    /**
     * The authenticator data of an assertion and the attestation object are decoded while the response is
     * deserialized, before any credential lookup or signature check.
     */
    #[Test]
    #[DataProvider('credentialsDeclaringAHugeByteString')]
    public function aCredentialDeclaringAHugeByteStringIsRejected(string $json): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage(sprintf('Out of range. Expected: %d, read: 5.', PHP_INT_MAX));

        $this->getSerializer()
            ->deserialize($json, PublicKeyCredential::class, 'json');
    }

    private static function credential(string $clientDataType, string $responseMembers): string
    {
        $clientDataJSON = sprintf(
            '{"type":"%s","challenge":"AAAA","origin":"https://example.com"}',
            $clientDataType
        );

        return sprintf(
            '{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{"clientDataJSON":"%s",%s}}',
            Base64UrlSafe::encodeUnpadded($clientDataJSON),
            $responseMembers
        );
    }
}
