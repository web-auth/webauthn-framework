<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Firewall;

use const JSON_THROW_ON_ERROR;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * @internal
 */
final class SecuredAreaTest extends WebTestCase
{
    private SessionInterface $session;

    private KernelBrowser $client;

    protected function setUp(): void
    {
        $this->client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $this->createSession();
    }

    /**
     * @test
     */
    public function aClientCannotAccessToTheResourceIfUserIsNotAuthenticated(): void
    {
        $this->client->request('GET', '/admin', [], [], [
            'HTTPS' => 'on',
        ]);

        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->client->getResponse()->getStatusCode());
        static::assertSame(
            '{"status":"error","errorMessage":"Full authentication is required to access this resource.","errorCode":0}',
            $this->client->getResponse()
                ->getContent()
        );
    }

    /**
     * @test
     */
    public function aClientCanSubmitUsernameToGetWebauthnOptions(): void
    {
        $body = [
            'username' => 'admin',
        ];
        $this->client->request('POST', '/login/options', [], [], [
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
        static::assertArrayHasKey('timeout', $json);

        static::assertArrayHasKey('set-cookie', $this->client->getResponse()->headers->all());
        static::assertTrue($this->session->has('FOO_BAR_SESSION_PARAMETER'));
    }

    /**
     * @test
     */
    public function aUserCannotBeBeAuthenticatedInAbsenceOfOptions(): void
    {
        $assertion = '{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"public-key","rawId":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MBAAAAew==","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ==","signature":"MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=","userHandle":null}}';

        $this->client->request('POST', '/login', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'test.com',
        ], $assertion);

        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->client->getResponse()->getStatusCode());
        static::assertSame(
            '{"status":"error","errorMessage":"No public key credential options available for this session.","errorCode":0}',
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
                ))
        ;

        $this->session->set('FOO_BAR_SESSION_PARAMETER', [
            'options' => $publicKeyCredentialRequestOptions,
            'userEntity' => new PublicKeyCredentialUserEntity('admin', 'foo', 'Foo BAR (-_-)'),
        ]);
        $this->session->save();

        $assertion = '{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"public-key","rawId":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MBAAAAew==","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ==","signature":"MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=","userHandle":null}}';

        $this->client->request('POST', '/login', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'localhost',
        ], $assertion);

        static::assertSame(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
        static::assertSame(
            '{"status":"ok","errorMessage":"","username":"admin"}',
            $this->client->getResponse()
                ->getContent()
        );
        static::assertTrue($this->session->has('_security_main'));
        static::assertTrue($this->client->getResponse()->headers->has('set-cookie'));

        $this->client->request('GET', '/admin', [], [], []);

        static::assertSame('["Hello admin"]', $this->client->getResponse()->getContent());
        static::assertSame(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
    }

    private function createSession(): void
    {
        /** @var SessionInterface $session */
        $this->session = self::getContainer()
            ->get('session.factory')
            ->createSession()
        ;

        $cookie = new Cookie($this->session->getName(), $this->session->getId());
        $this->client->getCookieJar()
            ->set($cookie)
        ;
    }
}
