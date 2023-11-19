<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Firewall;

use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\Bundle\Functional\CustomSessionStorage;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class SecuredAreaTest extends WebTestCase
{
    #[Test]
    public function aClientCannotAccessToTheResourceIfUserIsNotAuthenticated(): void
    {
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->request('GET', '/admin', [], [], [
            'HTTPS' => 'on',
        ]);

        static::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
    }

    #[Test]
    public function aClientCanSubmitUsernameToGetWebauthnOptions(): void
    {
        $body = [
            'username' => 'admin',
        ];
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->request('POST', '/api/login/options', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'test.com',
            'HTTPS' => 'on',
        ], json_encode($body, JSON_THROW_ON_ERROR));

        static::assertResponseIsSuccessful();
        $json = json_decode($client->getResponse()->getContent(), true, 512, JSON_THROW_ON_ERROR);
        static::assertArrayHasKey('challenge', $json);
        static::assertArrayHasKey('rpId', $json);
        static::assertArrayHasKey('userVerification', $json);
        static::assertArrayHasKey('allowCredentials', $json);
        static::assertArrayNotHasKey('timeout', $json);
    }

    #[Test]
    public function aUserCannotBeBeAuthenticatedInAbsenceOfOptions(): void
    {
        $assertion = '{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"public-key","rawId":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAew","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ","signature":"MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=","userHandle":null}}';
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->request('POST', '/api/login', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'test.com',
        ], $assertion);

        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
        static::assertSame(
            '{"status":"error","errorMessage":"No public key credential options available for this session."}',
            $client->getResponse()
                ->getContent()
        );
    }

    #[Test]
    public function aUserCanBeAuthenticatedAndAccessToTheProtectedResource(): void
    {
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions::create(
            base64_decode('G0JbLLndef3a0Iy3S2sSQA8uO4SO/ze6FZMAuPI6+xI=', true)
        );
        $publicKeyCredentialRequestOptions->timeout = 60000;
        $publicKeyCredentialRequestOptions->rpId = 'localhost';
        $publicKeyCredentialRequestOptions->userVerification = PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED;
        $publicKeyCredentialRequestOptions->allowCredentials = [
            PublicKeyCredentialDescriptor::create(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                Base64UrlSafe::decode(
                    'eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w'
                )
            ),
        ];

        $storage = static::getContainer()->get(CustomSessionStorage::class);
        $storage->store(Item::create(
            $publicKeyCredentialRequestOptions,
            PublicKeyCredentialUserEntity::create('admin', 'foo', 'Foo BAR (-_-)')
        ));

        $assertion = '{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"public-key","rawId":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAew","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ","signature":"MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=","userHandle":null}}';

        $client->request('POST', '/api/login', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'localhost',
        ], $assertion);

        static::assertResponseIsSuccessful();
        static::assertSame(
            '{"status":"ok","errorMessage":"","userIdentifier":"admin"}',
            $client->getResponse()
                ->getContent()
        );
        static::assertTrue($client->getRequest()->getSession()->has('_security_main'));

        $client->request('GET', '/admin');

        static::assertSame('["Hello admin"]', $client->getResponse()->getContent());
        static::assertResponseIsSuccessful();
    }
}
