<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Firewall;

use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\Bundle\Functional\CustomSessionStorage;
use Webauthn\Tests\Bundle\Functional\MultipleUserProvidersAppKernel;
use Webauthn\Tests\Bundle\Functional\PublicKeyCredentialUserEntityRepository;
use Webauthn\Tests\Bundle\Functional\User;
use Webauthn\Tests\Bundle\Functional\WebauthnTestCase;

/**
 * The "main" firewall names the "default" user provider and its custom authenticator returns a WebauthnPassport. The
 * "staff" provider is declared before "default" and knows the "root" and "admin" usernames too, with other roles. The
 * user of a WebauthnPassport must come from the provider of the firewall, not from the first provider of the
 * application that knows the username.
 *
 * @internal
 */
final class MultipleUserProvidersTest extends WebauthnTestCase
{
    #[Test]
    public function aRegistrationSignsInTheUserOfTheFirewallProvider(): void
    {
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->disableReboot();
        static::getContainer()->get(PublicKeyCredentialUserEntityRepository::class)->ensureUserDoesNotExist('root');
        static::getContainer()->get(PublicKeyCredentialSourceRepositoryInterface::class)->ensureCredentialNotExist(
            base64_decode('WT7a99M1zA3XUBBvEwXqPzP0C3zNoS/SpmMpv2sG2YM=', true)
        );

        /** @var SerializerInterface $serializer */
        $serializer = static::getContainer()->get(SerializerInterface::class);
        $publicKeyCredentialCreationOptions = $serializer->deserialize(
            '{"status":"ok","errorMessage":"","rp":{"name":"Webauthn Demo","id":"webauthn.spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-43},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39}],"challenge":"EhNVt3T8V12FJvSAc50nhKnZ-MEc-kf84xepDcGyN1g","attestation":"direct","user":{"name":"XY5nn3p_6olTLjoB2Jbb","id":"OTI5ZmJhMmYtMjM2MS00YmM2LWE5MTctYmI3NmFhMTRjN2Y5","displayName":"Bennie Moneypenny"},"authenticatorSelection":{"userVerification":"preferred"},"timeout":60000}',
            PublicKeyCredentialCreationOptions::class,
            'json'
        );
        static::getContainer()->get(CustomSessionStorage::class)->store(Item::create(
            $publicKeyCredentialCreationOptions,
            PublicKeyCredentialUserEntity::create('root', 'root', 'Root')
        ));

        $user = $this->signIn($client, '{"id":"WT7a99M1zA3XUBBvEwXqPzP0C3zNoS_SpmMpv2sG2YM","rawId":"WT7a99M1zA3XUBBvEwXqPzP0C3zNoS/SpmMpv2sG2YM","response":{"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZydjc2lnWECRl1RciDxSF7hkhJbqVJeryUIFrX7r6QQMQq8bIP4wYRA6f96iOO4wiOo34l65kZ5v1erxSmIaH56VySUSMusEaGF1dGhEYXRhWIGWBOqCgk6YpK2hS0Ri0Nc6jsRpEw2pGxkwdFkin3SjWUEAAAAykd_q15WeRHWtJpsNSCvgiQAgWT7a99M1zA3XUBBvEwXqPzP0C3zNoS_SpmMpv2sG2YOkAQEDJyAGIVgg4smTlXUJnAP_RqNWNv2Eqkh8I7ZDS0IuSgotbPygd9k","clientDataJSON":"eyJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLnNwb21reS1sYWJzLmNvbSIsImNoYWxsZW5nZSI6IkVoTlZ0M1Q4VjEyRkp2U0FjNTBuaEtuWi1NRWMta2Y4NHhlcERjR3lOMWciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"},"type":"public-key"}');

        static::assertInstanceOf(User::class, $user);
        static::assertSame(['ROLE_USER'], $user->getRoles());
        $client->request(Request::METHOD_GET, '/admin');
        static::assertResponseStatusCodeSame(403);
    }

    #[Test]
    public function anAuthenticationSignsInTheUserOfTheFirewallProvider(): void
    {
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->disableReboot();

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
        static::getContainer()->get(CustomSessionStorage::class)->store(Item::create(
            $publicKeyCredentialRequestOptions,
            PublicKeyCredentialUserEntity::create('admin', 'foo', 'Foo BAR (-_-)')
        ));

        $user = $this->signIn($client, '{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"public-key","rawId":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAew","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ","signature":"MEUCIEY_vcNkbo_LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w_8RGiZzE-gOM61ffxmgEDeyhM=","userHandle":null}}');

        static::assertInstanceOf(User::class, $user);
        static::assertSame(['ROLE_ADMIN', 'ROLE_USER'], $user->getRoles());
        $client->request(Request::METHOD_GET, '/admin');
        static::assertResponseIsSuccessful();
        static::assertSame('["Hello admin"]', $client->getResponse()->getContent());
    }

    protected static function getKernelClass(): string
    {
        return MultipleUserProvidersAppKernel::class;
    }

    private function signIn(KernelBrowser $client, string $response): UserInterface
    {
        $crawler = $client->request(Request::METHOD_GET, '/login');
        $client->submit($crawler->selectButton('login')->form(), [
            '_assertion' => $response,
        ]);
        static::assertResponseIsSuccessful();
        static::assertSame('{"success":true}', $client->getResponse()->getContent());

        $token = unserialize((string) $client->getRequest()->getSession()->get('_security_main'));
        static::assertInstanceOf(TokenInterface::class, $token);
        $user = $token->getUser();
        static::assertInstanceOf(UserInterface::class, $user);

        return $user;
    }
}
