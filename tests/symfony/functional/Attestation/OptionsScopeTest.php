<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Attestation;

use InvalidArgumentException;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnToken;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\Bundle\Functional\User;
use Webauthn\Tests\Bundle\Functional\WebauthnTestCase;

/**
 * Creation options issued by one endpoint cannot be redeemed at the result endpoint of another one
 * (GHSA-g9ff-w9h6-7ff3).
 *
 * The options storage of the test application returns the last options it stored, whatever the challenge, and the
 * kernel is not rebooted between the requests so that it keeps them. A recorded response therefore reaches the check
 * that compares the endpoint that issued the options with the one that receives the response.
 *
 * @internal
 */
final class OptionsScopeTest extends WebauthnTestCase
{
    private const ATTESTATION = '{"id":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK","type":"public-key","rawId":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiI5V3FncFJJWXZHTUNVWWlGVDIwbzFVN2hTRDE5M2sxMXp1NHRLUDd3UmNyRTI2enMxemM0TEh5UGludlBHUzg2d3U2YkR2cHdidDhYcDJiUTNWQlJTUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjkSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAYJjIobiMfS7pLMMQTjIzBw3+hADjTsu6nVoWkEO3TrVYkdnFQfzDW2cVEYtnL4ErykiC295iEnvZTzRvbGIKI7mOYjYp2DoOoUVcZptFbLLjRtqZtfkSLkxfQ1LRCWRBCqUBAgMmIAEhWCAcPxwKyHADVjTgTsat4R/Jax6PWte50A8ZasMm4w6RxCJYILt0FCiGwC6rBrh3ySNy0yiUjZpNGAhW+aM9YYyYnUTJ"}}';

    #[Test]
    public function aCreationControllerRefusesOptionsIssuedByTheFirewall(): void
    {
        $client = $this->createClientKeepingTheStoredOptions();
        $this->logIn($client);
        $this->postJson($client, '/api/register/options', json_encode([
            'username' => 'options-scope@foo.com',
            'displayName' => 'Options Scope',
        ], JSON_THROW_ON_ERROR));
        static::assertResponseIsSuccessful();

        $this->postJson($client, '/devices/add', self::ATTESTATION);

        static::assertResponseStatusCodeSame(400);
        static::assertSame(
            '{"status":"error","errorMessage":"The options were not issued by this endpoint."}',
            $client->getResponse()
                ->getContent()
        );
    }

    #[Test]
    public function theFirewallRefusesOptionsIssuedByACreationController(): void
    {
        $client = $this->createClientKeepingTheStoredOptions();
        $this->logIn($client);
        $this->postJson($client, '/devices/add/options', json_encode([], JSON_THROW_ON_ERROR));
        static::assertResponseIsSuccessful();

        $this->postJson($client, '/api/register', self::ATTESTATION);

        static::assertResponseStatusCodeSame(401);
        static::assertSame(
            '{"status":"error","errorMessage":"The options were not issued by this firewall."}',
            $client->getResponse()
                ->getContent()
        );
    }

    private function createClientKeepingTheStoredOptions(): KernelBrowser
    {
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->disableReboot();

        return $client;
    }

    private function postJson(KernelBrowser $client, string $path, string $body): void
    {
        $client->request(Request::METHOD_POST, $path, [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'localhost',
        ], $body);
    }

    /**
     * Signs the fixture user `admin` in on the firewall `main`, whose user provider reloads it by its username.
     */
    private function logIn(KernelBrowser $client): void
    {
        $firewallName = 'main';
        $userEntity = PublicKeyCredentialUserEntity::create('admin', 'foo', 'Foo BAR (-_-)');
        $user = User::create(
            $userEntity->name,
            $userEntity->id,
            $userEntity->displayName,
            null,
            ['ROLE_ADMIN', 'ROLE_USER']
        );
        $token = new WebauthnToken(
            $user,
            PublicKeyCredentialCreationOptions::create(
                PublicKeyCredentialRpEntity::create(),
                $userEntity,
                random_bytes(32)
            ),
            PublicKeyCredentialDescriptor::create(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                '0123456789'
            ),
            true,
            true,
            0,
            0,
            100,
            null,
            $firewallName,
            $user->getRoles(),
            true,
            true
        );
        $token->setUser($user);

        $container = static::getContainer();
        $container->get('security.untracked_token_storage')
            ->setToken($token);
        $container->has('session.factory') || throw new InvalidArgumentException('No session factory');
        $session = $container->get('session.factory')
            ->createSession();
        $session->set('_security_' . $firewallName, serialize($token));
        $session->save();
        $client->getCookieJar()
            ->set(new Cookie($session->getName(), $session->getId()));
    }
}
