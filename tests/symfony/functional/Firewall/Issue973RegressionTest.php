<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Firewall;

use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Webauthn\Tests\Bundle\Functional\WebauthnTestCase;

/**
 * Issue #973: a malformed or bot request to a result path logged PHP warnings before being rejected. A body without
 * "id" is covered by LegacySecuredAreaTest. A response object with a missing member still logged "Undefined array key"
 * warnings, and a member with the wrong type sent the TypeError message back to the client. Both are now rejected with
 * the InvalidDataException the denormalizers throw before reading the member.
 *
 * @see https://github.com/web-auth/webauthn-framework/issues/973
 * @internal
 */
final class Issue973RegressionTest extends WebauthnTestCase
{
    /**
     * @return iterable<string, array{string, string, int, string}>
     */
    public static function malformedResultRequests(): iterable
    {
        yield 'authentication, incomplete assertion response' => [
            '/api/login',
            '{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{"signature":"AAAA"}}',
            Response::HTTP_UNAUTHORIZED,
            'Missing authenticatorData',
        ];
        yield 'authentication, id that is not a string' => [
            '/api/login',
            '{"id":1,"rawId":"AAAA","type":"public-key","response":{"signature":"AAAA"}}',
            Response::HTTP_UNAUTHORIZED,
            'Invalid parameter "id". Shall be a string.',
        ];
        yield 'registration, incomplete attestation response' => [
            '/api/register',
            '{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{"attestationObject":"AAAA"}}',
            Response::HTTP_UNAUTHORIZED,
            'Missing clientDataJSON',
        ];
        yield 'assertion controller, incomplete assertion response' => [
            '/devices/test',
            '{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{"signature":"AAAA"}}',
            Response::HTTP_BAD_REQUEST,
            'Missing authenticatorData',
        ];
    }

    #[Test]
    #[DataProvider('malformedResultRequests')]
    public function aMalformedPublicKeyCredentialIsRejectedWithTheDenormalizerError(
        string $path,
        string $body,
        int $expectedStatusCode,
        string $expectedMessage
    ): void {
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->request(Request::METHOD_POST, $path, [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'localhost',
        ], $body);

        self::assertResponseStatusCodeSame($expectedStatusCode);
        static::assertSame(
            [
                'status' => 'error',
                'errorMessage' => $expectedMessage,
            ],
            json_decode((string) $client->getResponse()->getContent(), true, 512, JSON_THROW_ON_ERROR)
        );
    }
}
