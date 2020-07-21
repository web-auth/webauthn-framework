<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Tests\Functional\Profile;

use Prophecy\PhpUnit\ProphecyTrait;
use function Safe\json_decode;
use function Safe\json_encode;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * @group functional
 *
 * @internal
 */
class TransportBindingProfileCreationTest extends WebTestCase
{
    use ProphecyTrait;

    /**
     * @test
     */
    public function aRequestWithoutUsernameCannotBeProcessed(): void
    {
        $content = [
            'displayName' => 'FOO',
        ];
        $client = self::createClient([], ['HTTPS' => 'on']);
        $client->request(Request::METHOD_POST, '/attestation/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com'], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals($data['status'], 'failed');
        static::assertEquals(400, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals($data['errorMessage'], 'username: This value should not be blank.');
    }

    /**
     * @test
     */
    public function aRequestWithoutDisplayNameCannotBeProcessed(): void
    {
        $content = [
            'username' => 'foo',
        ];
        $client = self::createClient([], ['HTTPS' => 'on']);
        $client->request(Request::METHOD_POST, '/attestation/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com'], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals($data['status'], 'failed');
        static::assertEquals(400, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals($data['errorMessage'], 'displayName: This value should not be blank.');
    }

    /**
     * @test
     */
    public function aRequestWithADisplayNameCannotBeProcessed(): void
    {
        $content = [
            'username' => 'foo',
            'displayName' => 123,
        ];
        $client = self::createClient([], ['HTTPS' => 'on']);
        $client->request(Request::METHOD_POST, '/attestation/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com'], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals($data['status'], 'failed');
        static::assertEquals(400, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals('displayName: This value should be of type string.', $data['errorMessage']);
    }

    /**
     * @test
     */
    public function aRequestWithAnInvalidUsernameCannotBeProcessed(): void
    {
        $content = [
            'username' => 123,
            'displayName' => 'FOO',
        ];
        $client = self::createClient([], ['HTTPS' => 'on']);
        $client->request(Request::METHOD_POST, '/attestation/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com'], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals($data['status'], 'failed');
        static::assertEquals(400, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals($data['errorMessage'], 'username: This value should be of type string.');
    }

    /**
     * @test
     */
    public function aValidRequestProcessed(): void
    {
        $content = [
            'username' => 'foo',
            'displayName' => 'FOO',
            'authenticatorSelection' => [
                'authenticatorAttachment' => 'cross-platform',
                'userVerification' => 'preferred',
                'requireResidentKey' => true,
            ],
            'attestation' => 'indirect',
        ];
        $client = self::createClient([], ['HTTPS' => 'on']);
        $client->request(Request::METHOD_POST, '/attestation/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'localhost'], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals('ok', $data['status']);
        static::assertEquals(200, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals($data['errorMessage'], '');

        static::assertArrayHasKey('attestation', $data);
        static::assertEquals($data['attestation'], 'indirect');

        static::assertArrayHasKey('authenticatorSelection', $data);
        static::assertEquals($data['authenticatorSelection'], ['authenticatorAttachment' => 'cross-platform', 'userVerification' => 'preferred', 'requireResidentKey' => true]);
    }

    /**
     * @test
     */
    public function aValidRequestProcessedOnOtherHost(): void
    {
        $content = [
            'username' => 'foo',
            'displayName' => 'FOO',
            'authenticatorSelection' => ['requireResidentKey' => true],
        ];
        $client = self::createClient([], ['HTTPS' => 'on']);
        $client->request(Request::METHOD_POST, '/attestation/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'webauth.app'], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals('ok', $data['status']);
        static::assertEquals(200, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals($data['errorMessage'], '');

        static::assertArrayHasKey('attestation', $data);
        static::assertEquals('none', $data['attestation']);

        static::assertArrayHasKey('authenticatorSelection', $data);
        static::assertEquals(['userVerification' => 'preferred', 'requireResidentKey' => true], $data['authenticatorSelection']);
    }

    /**
     * @test
     */
    public function aValidRequestProcessedWithMinimalOptions(): void
    {
        $content = [
            'username' => 'foo',
            'displayName' => 'FOO',
            'authenticatorSelection' => [
                'authenticatorAttachment' => 'platform',
                'userVerification' => 'required',
                'requireResidentKey' => true,
            ],
        ];
        $client = self::createClient([], ['HTTPS' => 'on']);
        $client->request(Request::METHOD_POST, '/attestation/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com'], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals('ok', $data['status']);
        static::assertEquals(200, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals($data['errorMessage'], '');

        static::assertArrayHasKey('attestation', $data);
        static::assertEquals('none', $data['attestation']);

        static::assertArrayHasKey('authenticatorSelection', $data);
        static::assertEquals(['authenticatorAttachment' => 'platform', 'userVerification' => 'required', 'requireResidentKey' => true], $data['authenticatorSelection']);
    }
}
