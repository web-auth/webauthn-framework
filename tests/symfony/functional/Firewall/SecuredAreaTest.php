<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Firewall;

use const JSON_THROW_ON_ERROR;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\Bundle\Functional\CustomSessionStorage;

/**
 * @internal
 */
final class SecuredAreaTest extends WebTestCase
{
    private KernelBrowser $client;

    private OptionsStorage $storage;

    protected function setUp(): void
    {
        $this->client = static::createClient([], [
            'HTTPS' => 'on',
        ]);

        $this->storage = static::getContainer()->get(CustomSessionStorage::class);
    }

    /**
     * @test
     */
    public function aClientCannotAccessToTheResourceIfUserIsNotAuthenticated(): void
    {
        $this->client->request('GET', '/admin', [], [], [
            'HTTPS' => 'on',
        ]);

        static::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
    }

    /**
     * @test
     */
    public function aClientCanSubmitUsernameToGetWebauthnOptions(): void
    {
        $body = [
            'username' => 'admin',
        ];
        $this->client->request('POST', '/api/login/options', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'test.com',
            'HTTPS' => 'on',
        ], json_encode($body, JSON_THROW_ON_ERROR));

        static::assertSame(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
        $json = json_decode($this->client->getResponse()->getContent(), true, 512, JSON_THROW_ON_ERROR);
        static::assertArrayHasKey('challenge', $json);
        static::assertArrayHasKey('rpId', $json);
        static::assertArrayHasKey('userVerification', $json);
        static::assertArrayHasKey('allowCredentials', $json);
        static::assertArrayNotHasKey('timeout', $json);
    }

    /**
     * @test
     */
    public function aUserCannotBeBeAuthenticatedInAbsenceOfOptions(): void
    {
        $assertion = '{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"public-key","rawId":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAew","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ","signature":"MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=","userHandle":null}}';

        $this->client->request('POST', '/api/login', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'test.com',
        ], $assertion);

        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
        static::assertSame(
            '{"status":"error","errorMessage":"No public key credential options available for this session.","errorCode":15}',
            $this->client->getResponse()
                ->getContent()
        );
    }

    /**
     * @test
     */
    public function aUserCanBeAuthenticatedAndAccessToTheProtectedResource(): void
    {
        $publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions
            ::create(base64_decode('G0JbLLndef3a0Iy3S2sSQA8uO4SO/ze6FZMAuPI6+xI=', true))
                ->setTimeout(60000)
                ->setRpId('localhost')
                ->setUserVerification(PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED)
                ->allowCredential(new PublicKeyCredentialDescriptor(
                    PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                    Base64UrlSafe::decode(
                        'eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w'
                    )
                ));

        $this->storage->store(Item::create(
            $publicKeyCredentialRequestOptions,
            PublicKeyCredentialUserEntity::create('admin', 'foo', 'Foo BAR (-_-)')
        ));

        $assertion = '{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"public-key","rawId":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAew","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ","signature":"MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=","userHandle":null}}';

        $this->client->request('POST', '/api/login', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'localhost',
        ], $assertion);

        static::assertSame(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
        static::assertSame(
            '{"status":"ok","errorMessage":"","userId":"Zm9v"}',
            $this->client->getResponse()
                ->getContent()
        );
        static::assertTrue($this->client->getRequest()->getSession()->has('_security_main'));

        $this->client->request('GET', '/admin', [], [], []);

        static::assertSame('["Hello foo"]', $this->client->getResponse()->getContent());
        static::assertSame(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
    }
}
