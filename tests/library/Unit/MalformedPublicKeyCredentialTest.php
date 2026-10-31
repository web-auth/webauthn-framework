<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use const E_NOTICE;
use const E_WARNING;
use ErrorException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\Exception\InvalidDataException;
use Webauthn\PublicKeyCredential;
use Webauthn\Tests\AbstractTestCase;

/**
 * A public key credential is sent by the client. Since #975, PublicKeyCredentialDenormalizer rejects a credential
 * without "id", "rawId", "type" or "response" (see SerializerTest). The denormalizers also reject a body that is not
 * an object, a member that has the wrong type and a response object with a missing or mistyped member, with an
 * InvalidDataException and before reading it. Reading it first raised "Undefined array key" warnings and TypeErrors.
 *
 * @see https://github.com/web-auth/webauthn-framework/issues/973
 * @internal
 */
final class MalformedPublicKeyCredentialTest extends AbstractTestCase
{
    /**
     * @return iterable<string, array{class-string, string, string}>
     */
    public static function malformedPublicKeyCredentials(): iterable
    {
        yield 'credential that is not an object' => [
            PublicKeyCredential::class,
            '"public-key"',
            'Invalid public key credential. Shall be an object.',
        ];
        yield 'credential with an id that is not a string' => [
            PublicKeyCredential::class,
            '{"id":1,"rawId":"AAAA","type":"public-key","response":{}}',
            'Invalid parameter "id". Shall be a string.',
        ];
        yield 'credential with a rawId that is not a string' => [
            PublicKeyCredential::class,
            '{"id":"AAAA","rawId":[],"type":"public-key","response":{}}',
            'Invalid parameter "rawId". Shall be a string.',
        ];
        yield 'credential with a type that is not a string' => [
            PublicKeyCredential::class,
            '{"id":"AAAA","rawId":"AAAA","type":null,"response":{}}',
            'Invalid parameter "type". Shall be a string.',
        ];
        yield 'credential with a response that is not an object' => [
            PublicKeyCredential::class,
            '{"id":"AAAA","rawId":"AAAA","type":"public-key","response":"AAAA"}',
            'Invalid parameter "response". Shall be an object.',
        ];
        yield 'assertion response that is not an object' => [
            AuthenticatorAssertionResponse::class,
            '"AAAA"',
            'Invalid authenticator assertion response. Shall be an object.',
        ];
        yield 'assertion response without authenticatorData' => [
            PublicKeyCredential::class,
            self::credentialWithResponse('{"signature":"AAAA","clientDataJSON":"e30"}'),
            'Missing authenticatorData',
        ];
        yield 'assertion response with a signature that is not a string' => [
            PublicKeyCredential::class,
            self::credentialWithResponse('{"authenticatorData":"AAAA","signature":1,"clientDataJSON":"e30"}'),
            'Invalid parameter "signature". Shall be a string.',
        ];
        yield 'assertion response without clientDataJSON' => [
            PublicKeyCredential::class,
            self::credentialWithResponse('{"authenticatorData":"AAAA","signature":"AAAA"}'),
            'Missing clientDataJSON',
        ];
        yield 'attestation response that is not an object' => [
            AuthenticatorAttestationResponse::class,
            '"AAAA"',
            'Invalid authenticator attestation response. Shall be an object.',
        ];
        yield 'attestation response without clientDataJSON' => [
            PublicKeyCredential::class,
            self::credentialWithResponse('{"attestationObject":"AAAA"}'),
            'Missing clientDataJSON',
        ];
        yield 'attestation response with an attestationObject that is not a string' => [
            PublicKeyCredential::class,
            self::credentialWithResponse('{"clientDataJSON":"e30","attestationObject":1}'),
            'Invalid parameter "attestationObject". Shall be a string.',
        ];
    }

    /**
     * @param class-string $class
     */
    #[Test]
    #[DataProvider('malformedPublicKeyCredentials')]
    public function aMalformedPublicKeyCredentialIsRejectedBeforeAnyMemberIsRead(
        string $class,
        string $json,
        string $expectedMessage
    ): void {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage($expectedMessage);

        $this->deserializeFailingOnWarnings($json, $class);
    }

    private static function credentialWithResponse(string $response): string
    {
        return '{"id":"AAAA","rawId":"AAAA","type":"public-key","response":' . $response . '}';
    }

    /**
     * Turns any PHP warning or notice into an ErrorException, so that reading a missing member ("Undefined array key")
     * fails the test instead of being only reported by PHPUnit.
     *
     * @param class-string $class
     */
    private function deserializeFailingOnWarnings(string $json, string $class): void
    {
        set_error_handler(static function (int $severity, string $message, string $file, int $line): never {
            throw new ErrorException($message, 0, $severity, $file, $line);
        }, E_WARNING | E_NOTICE);

        try {
            $this->getSerializer()
                ->deserialize($json, $class, 'json');
        } finally {
            restore_error_handler();
        }
    }
}
