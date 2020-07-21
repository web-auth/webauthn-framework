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

namespace Webauthn\Bundle\Tests\Functional\Attestation;

use function count;
use Prophecy\PhpUnit\ProphecyTrait;
use function Safe\json_encode;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnToken;
use Webauthn\Bundle\Tests\Functional\PublicKeyCredentialSourceRepository;
use Webauthn\Bundle\Tests\Functional\User;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;

/**
 * @group functional
 *
 * @internal
 */
class AdditionalAuthenticatorTest extends WebTestCase
{
    use ProphecyTrait;

    /**
     * @var KernelBrowser
     */
    private $client;

    protected function setUp(): void
    {
        $this->client = static::createClient([], ['HTTPS' => 'on']);
    }

    /**
     * @test
     */
    public function anExistingUserCanAddAskForOptionsUsingTheDedicatedController(): void
    {
        $this->logIn();
        $this->client->request(Request::METHOD_POST, '/devices/add/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com'], json_encode([]));
        $response = $this->client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertEquals(200, $response->getStatusCode());
        static::assertIsArray($data);
        $expectedKeys = ['status', 'errorMessage', 'rp', 'pubKeyCredParams', 'challenge', 'attestation', 'user', 'authenticatorSelection', 'timeout'];
        foreach ($expectedKeys as $expectedKey) {
            static::assertArrayHasKey($expectedKey, $data);
        }
        static::assertEquals('ok', $data['status']);

        /** @var SessionInterface $session */
        $session = self::$container->get('session');
        static::assertTrue($session->has('WEBAUTHN_PUBLIC_KEY_OPTIONS'));
    }

    /**
     * @test
     */
    public function withTheOptionAnExistingUserCanRegisterNewAnotherAuthenticator(): void
    {
        /** @var PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository */
        $publicKeyCredentialSourceRepository = self::$kernel
            ->getContainer()
            ->get(PublicKeyCredentialSourceRepository::class)
        ;
        $this->logIn();
        $options = '{"status":"ok","errorMessage":"","rp":{"name":"Webauthn Demo","id":"webauthn.spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-43},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39}],"challenge":"EhNVt3T8V12FJvSAc50nhKnZ-MEc-kf84xepDcGyN1g","attestation":"direct","user":{"name":"XY5nn3p_6olTLjoB2Jbb","id":"OTI5ZmJhMmYtMjM2MS00YmM2LWE5MTctYmI3NmFhMTRjN2Y5","displayName":"Bennie Moneypenny"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":60000}';

        /** @var PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions */
        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::createFromString($options);

        $session = self::$container->get('session');
        $session->set('WEBAUTHN_PUBLIC_KEY_OPTIONS', [
            'options' => $publicKeyCredentialCreationOptions,
            'userEntity' => $publicKeyCredentialCreationOptions->getUser(),
        ]);
        $session->save();

        $numberOfRegisteredCredentials = count($publicKeyCredentialSourceRepository->findAllForUserEntity($publicKeyCredentialCreationOptions->getUser()));
        $body = '{"id":"WT7a99M1zA3XUBBvEwXqPzP0C3zNoS_SpmMpv2sG2YM","rawId":"WT7a99M1zA3XUBBvEwXqPzP0C3zNoS_SpmMpv2sG2YM","response":{"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZydjc2lnWECRl1RciDxSF7hkhJbqVJeryUIFrX7r6QQMQq8bIP4wYRA6f96iOO4wiOo34l65kZ5v1erxSmIaH56VySUSMusEaGF1dGhEYXRhWIGWBOqCgk6YpK2hS0Ri0Nc6jsRpEw2pGxkwdFkin3SjWUEAAAAykd_q15WeRHWtJpsNSCvgiQAgWT7a99M1zA3XUBBvEwXqPzP0C3zNoS_SpmMpv2sG2YOkAQEDJyAGIVgg4smTlXUJnAP_RqNWNv2Eqkh8I7ZDS0IuSgotbPygd9k","clientDataJSON":"eyJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLnNwb21reS1sYWJzLmNvbSIsImNoYWxsZW5nZSI6IkVoTlZ0M1Q4VjEyRkp2U0FjNTBuaEtuWi1NRWMta2Y4NHhlcERjR3lOMWciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"},"type":"public-key"}';
        $this->client->request(
            Request::METHOD_POST,
            '/devices/add',
            [],
            [],
            ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com'],
            $body
        );
        $response = $this->client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertEquals(201, $response->getStatusCode());
        static::assertIsArray($data);
        $expectedKeys = ['status', 'errorMessage'];
        foreach ($expectedKeys as $expectedKey) {
            static::assertArrayHasKey($expectedKey, $data);
        }
        static::assertEquals('ok', $data['status']);

        /** @var SessionInterface $session */
        $session = self::$container->get('session');
        static::assertFalse($session->has('WEBAUTHN_PUBLIC_KEY_OPTIONS'));

        $newNumberOfRegisteredCredentials = count($publicKeyCredentialSourceRepository->findAllForUserEntity($publicKeyCredentialCreationOptions->getUser()));
        static::assertEquals($numberOfRegisteredCredentials + 1, $newNumberOfRegisteredCredentials);
    }

    private function logIn(): void
    {
        $session = self::$container->get('session');
        $options = '{"status":"ok","errorMessage":"","rp":{"name":"Webauthn Demo","id":"webauthn.spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-43},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39}],"challenge":"EhNVt3T8V12FJvSAc50nhKnZ-MEc-kf84xepDcGyN1g","attestation":"direct","user":{"name":"XY5nn3p_6olTLjoB2Jbb","id":"OTI5ZmJhMmYtMjM2MS00YmM2LWE5MTctYmI3NmFhMTRjN2Y5","displayName":"Bennie Moneypenny"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":60000}';
        /** @var PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions */
        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::createFromString($options);
        $user = new User(
            $publicKeyCredentialCreationOptions->getUser()->getName(),
            $publicKeyCredentialCreationOptions->getUser()->getId(),
            $publicKeyCredentialCreationOptions->getUser()->getDisplayName(),
            null,
            ['ROLE_ADMIN', 'ROLE_USER']
        );

        $firewallName = 'main';
        $firewallContext = 'main';

        $token = new WebauthnToken(
            $user,
            $publicKeyCredentialCreationOptions,
            new PublicKeyCredentialDescriptor(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, '0123456789'),
            true,
            false,
            0,
            0,
            100,
            null,
            $firewallName,
            $user->getRoles()
        );
        $token->setUser($user);
        $token->setAuthenticated(true);
        $session->set('_security_'.$firewallContext, serialize($token));
        $session->save();

        $cookie = new Cookie(
            $session->getName(),
            $session->getId()
        );
        $this->client->getCookieJar()->set($cookie);
    }
}
