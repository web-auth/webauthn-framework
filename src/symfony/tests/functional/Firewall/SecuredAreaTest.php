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

namespace Webauthn\Bundle\Tests\Functional\Firewall;

use Base64Url\Base64Url;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * @group functional
 *
 * @internal
 */
class SecuredAreaTest extends WebTestCase
{
    /**
     * @test
     */
    public function aClientCannotAccessToTheResourceIfUserIsNotAuthenticated(): void
    {
        $client = static::createClient();
        $client->request('GET', '/admin', [], [], ['HTTPS' => 'on']);

        static::assertEquals(Response::HTTP_UNAUTHORIZED, $client->getResponse()->getStatusCode());
        static::assertEquals('{"status":"error","errorMessage":"Full authentication is required to access this resource.","errorCode":0}', $client->getResponse()->getContent());
    }

    /**
     * @test
     */
    public function aClientCanSubmitUsernameToGetWebauthnOptions(): void
    {
        $body = [
            'username' => 'admin',
        ];
        $client = static::createClient();
        $client->request('POST', '/login/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com', 'HTTPS' => 'on'], json_encode($body));

        static::assertEquals(Response::HTTP_OK, $client->getResponse()->getStatusCode());
        $json = json_decode($client->getResponse()->getContent(), true);
        static::assertArrayHasKey('challenge', $json);
        static::assertArrayHasKey('rpId', $json);
        static::assertArrayHasKey('userVerification', $json);
        static::assertArrayHasKey('allowCredentials', $json);
        static::assertArrayHasKey('timeout', $json);

        static::assertArrayHasKey('set-cookie', $client->getResponse()->headers->all());
        $session = $client->getContainer()->get('session');
        static::assertTrue($session->has('FOO_BAR_SESSION_PARAMETER'));
    }

    /**
     * @test
     */
    public function aUserCannotBeBeAuthenticatedInAbsenceOfOptions(): void
    {
        $client = static::createClient();
        $assertion = '{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"public-key","rawId":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MBAAAAew==","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ==","signature":"MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=","userHandle":null}}';

        $client->request('POST', '/login', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com', 'HTTPS' => 'on'], $assertion);

        static::assertEquals(Response::HTTP_UNAUTHORIZED, $client->getResponse()->getStatusCode());
        static::assertEquals('{"status":"error","errorMessage":"No public key credential options available for this session.","errorCode":0}', $client->getResponse()->getContent());
    }

    /**
     * @test
     */
    public function aUserCanBeAuthenticatedAndAccessToTheProtectedResource(): void
    {
        $publicKeyCredentialRequestOptions = new PublicKeyCredentialRequestOptions(
            base64_decode('G0JbLLndef3a0Iy3S2sSQA8uO4SO/ze6FZMAuPI6+xI=', true),
            60000,
            'localhost',
            [
                new PublicKeyCredentialDescriptor(
                    PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                    Base64Url::decode('eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w')
                ),
            ],
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            new AuthenticationExtensionsClientInputs()
        );

        $client = static::createClient();
        $session = $client->getContainer()->get('session');
        $session->set('FOO_BAR_SESSION_PARAMETER', [
            'options' => $publicKeyCredentialRequestOptions,
            'userEntity' => new PublicKeyCredentialUserEntity('admin', 'foo', 'Foo BAR (-_-)'),
        ]);
        $session->save();

        $assertion = '{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"public-key","rawId":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MBAAAAew==","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ==","signature":"MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=","userHandle":null}}';

        $client->request('POST', '/login', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'localhost', 'HTTPS' => 'on'], $assertion);

        static::assertEquals(Response::HTTP_OK, $client->getResponse()->getStatusCode());
        static::assertEquals('{"status":"ok","errorMessage":"","username":"admin"}', $client->getResponse()->getContent());
        static::assertTrue($session->has('_security_main'));
        static::assertTrue($client->getResponse()->headers->has('set-cookie'));

        $client->request('GET', '/admin', [], [], ['HTTPS' => 'on']);

        static::assertEquals(Response::HTTP_OK, $client->getResponse()->getStatusCode());
        static::assertEquals('["Hello admin"]', $client->getResponse()->getContent());
    }
}
