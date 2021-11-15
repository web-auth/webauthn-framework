<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Tests\Functional\Profile;

use const JSON_THROW_ON_ERROR;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Request;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * @internal
 */
final class TransportBindingProfileAssertionTest extends WebTestCase
{
    /**
     * @test
     */
    public function aRequestWithoutUsernameCannotBeProcessed(): void
    {
        $content = [];
        $client = self::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->request(Request::METHOD_POST, '/assertion/options', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'test.com',
        ], json_encode($content, JSON_THROW_ON_ERROR));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true, 512, JSON_THROW_ON_ERROR);

        static::assertArrayHasKey('status', $data);
        static::assertSame('ok', $data['status']);
        static::assertSame(200, $client->getResponse()->getStatusCode());
    }

    /**
     * @test
     */
    public function aValidRequestProcessed(): void
    {
        $content = [
            'username' => 'admin',
            'userVerification' => PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
        ];
        $client = self::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->request(Request::METHOD_POST, '/assertion/options', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'localhost',
        ], json_encode($content, JSON_THROW_ON_ERROR));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true, 512, JSON_THROW_ON_ERROR);
        static::assertArrayHasKey('status', $data);
        static::assertSame('ok', $data['status']);
        static::assertSame(200, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertSame('', $data['errorMessage']);

        static::assertArrayHasKey('userVerification', $data);
        static::assertSame(
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
            $data['userVerification']
        );
    }
}
