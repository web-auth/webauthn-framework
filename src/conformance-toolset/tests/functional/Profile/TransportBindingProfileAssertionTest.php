<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\ConformanceToolset\Tests\Functional\Profile;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Request;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * @group functional
 */
class TransportBindingProfileAssertionTest extends WebTestCase
{
    /**
     * @test
     */
    public function aRequestWithoutUsernameCannotBeProcessed(): void
    {
        $content = [
        ];
        $client = self::createClient([], ['HTTPS' => 'on']);
        $client->request(Request::METHOD_POST, '/assertion/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com'], \Safe\json_encode($content));
        $response = $client->getResponse();
        $data = \Safe\json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals('failed', $data['status']);
        static::assertEquals(400, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals($data['errorMessage'], 'username: This value should not be blank.');
    }

    /**
     * @test
     */
    public function aRequestWithAnInvalidUsernameCannotBeProcessed(): void
    {
        $content = [
            'username' => 123,
        ];
        $client = self::createClient([], ['HTTPS' => 'on']);
        $client->request(Request::METHOD_POST, '/assertion/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com'], \Safe\json_encode($content));
        $response = $client->getResponse();
        $data = \Safe\json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals('failed', $data['status']);
        static::assertEquals(400, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals('username: This value should be of type string.', $data['errorMessage']);
    }

    /**
     * @test
     */
    public function aValidRequestProcessed(): void
    {
        $content = [
            'username' => 'username',
            'userVerification' => PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
        ];
        $client = self::createClient([], ['HTTPS' => 'on']);
        $client->request(Request::METHOD_POST, '/assertion/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com'], \Safe\json_encode($content));
        $response = $client->getResponse();
        $data = \Safe\json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals('ok', $data['status']);
        static::assertEquals(200, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals($data['errorMessage'], '');

        static::assertArrayHasKey('userVerification', $data);
        static::assertEquals(PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_DISCOURAGED, $data['userVerification']);
    }
}
