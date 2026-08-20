<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Firewall;

use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\Bundle\Functional\CustomSessionStorage;
use Webauthn\Tests\Bundle\Functional\PublicKeyCredentialUserEntityRepository;
use Webauthn\Tests\Bundle\Functional\WebauthnTestCase;

/**
 * @internal
 */
final class SecuredAreaTest extends WebauthnTestCase
{
    #[Test]
    public function aClientIsRedirectedIfUserIsNotAuthenticated(): void
    {
        // Given
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);

        // When
        $client->request(Request::METHOD_GET, '/admin');

        // Then
        static::assertResponseRedirects('/login');
    }

    #[Test]
    public function aUserCannotBeAuthenticatedInAbsenceOfOptions(): void
    {
        // Given
        $assertion = '{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"public-key","rawId":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAew","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ","signature":"MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=","userHandle":null}}';

        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->disableReboot();
        $crawler = $client->request(Request::METHOD_GET, '/login');

        // When
        $form = $crawler->selectButton('login')
            ->form();
        $client->submit($form, [
            '_assertion' => $assertion,
        ]);

        // Then
        static::assertResponseRedirects('/login');
        // @todo: verify the reason is: No public key credential options available for this session.
    }

    #[Test]
    public function aUserCanBeAuthenticatedAndAccessToTheProtectedResource(): void
    {
        // Given
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

        $storage = static::getContainer()->get(CustomSessionStorage::class);
        $storage->store(Item::create(
            $publicKeyCredentialRequestOptions,
            PublicKeyCredentialUserEntity::create('admin', 'foo', 'Foo BAR (-_-)')
        ));

        $assertion = '{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"public-key","rawId":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAew","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ","signature":"MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=","userHandle":null}}';

        $crawler = $client->request(Request::METHOD_GET, '/login');

        // When
        $form = $crawler->selectButton('login')
            ->form();
        $client->submit($form, [
            '_assertion' => $assertion,
        ]);

        // Then
        static::assertResponseIsSuccessful();
        static::assertSame('{"success":true}', $client->getResponse()->getContent());
        static::assertTrue($client->getRequest()->getSession()->has('_security_main'));

        // And then
        $client->request(Request::METHOD_GET, '/admin');
        static::assertSame('["Hello admin"]', $client->getResponse()->getContent());
        static::assertResponseIsSuccessful();
    }

    #[Test]
    public function aUserCannotBeRegisteredAsTheUserAlreadyExists(): void
    {
        // Given
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->disableReboot();
        /** @var SerializerInterface $serializer */
        $serializer = static::getContainer()->get(SerializerInterface::class);

        $options = '{"status":"ok","errorMessage":"","rp":{"name":"Webauthn Demo","id":"webauthn.spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-43},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39}],"challenge":"EhNVt3T8V12FJvSAc50nhKnZ-MEc-kf84xepDcGyN1g","attestation":"direct","user":{"name":"XY5nn3p_6olTLjoB2Jbb","id":"OTI5ZmJhMmYtMjM2MS00YmM2LWE5MTctYmI3NmFhMTRjN2Y5","displayName":"Bennie Moneypenny"},"authenticatorSelection":{"userVerification":"preferred"},"timeout":60000}';
        $publicKeyCredentialCreationOptions = $serializer->deserialize(
            $options,
            PublicKeyCredentialCreationOptions::class,
            'json'
        );

        $storage = static::getContainer()->get(CustomSessionStorage::class);
        $storage->store(Item::create(
            $publicKeyCredentialCreationOptions,
            PublicKeyCredentialUserEntity::create('admin', 'foo', 'Foo BAR (-_-)')
        ));

        $assertion = '{"id":"WT7a99M1zA3XUBBvEwXqPzP0C3zNoS_SpmMpv2sG2YM","rawId":"WT7a99M1zA3XUBBvEwXqPzP0C3zNoS/SpmMpv2sG2YM","response":{"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZydjc2lnWECRl1RciDxSF7hkhJbqVJeryUIFrX7r6QQMQq8bIP4wYRA6f96iOO4wiOo34l65kZ5v1erxSmIaH56VySUSMusEaGF1dGhEYXRhWIGWBOqCgk6YpK2hS0Ri0Nc6jsRpEw2pGxkwdFkin3SjWUEAAAAykd_q15WeRHWtJpsNSCvgiQAgWT7a99M1zA3XUBBvEwXqPzP0C3zNoS_SpmMpv2sG2YOkAQEDJyAGIVgg4smTlXUJnAP_RqNWNv2Eqkh8I7ZDS0IuSgotbPygd9k","clientDataJSON":"eyJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLnNwb21reS1sYWJzLmNvbSIsImNoYWxsZW5nZSI6IkVoTlZ0M1Q4VjEyRkp2U0FjNTBuaEtuWi1NRWMta2Y4NHhlcERjR3lOMWciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"},"type":"public-key"}';

        $crawler = $client->request(Request::METHOD_GET, '/login');

        // When
        $form = $crawler->selectButton('login')
            ->form();
        $client->submit($form, [
            '_assertion' => $assertion,
        ]);

        // Then
        static::assertResponseRedirects('/login');
    }

    #[Test]
    public function aUserCanBeRegistered(): void
    {
        // Given
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->disableReboot();
        $userEntityRepository = static::getContainer()->get(PublicKeyCredentialUserEntityRepository::class);
        $userEntityRepository->ensureUserDoesNotExist('john');
        $credentialRepository = static::getContainer()->get(PublicKeyCredentialSourceRepositoryInterface::class);
        $credentialRepository->ensureCredentialNotExist(
            base64_decode('WT7a99M1zA3XUBBvEwXqPzP0C3zNoS/SpmMpv2sG2YM=', true)
        );

        /** @var SerializerInterface $serializer */
        $serializer = static::getContainer()->get(SerializerInterface::class);

        $options = '{"status":"ok","errorMessage":"","rp":{"name":"Webauthn Demo","id":"webauthn.spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-43},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39}],"challenge":"EhNVt3T8V12FJvSAc50nhKnZ-MEc-kf84xepDcGyN1g","attestation":"direct","user":{"name":"XY5nn3p_6olTLjoB2Jbb","id":"OTI5ZmJhMmYtMjM2MS00YmM2LWE5MTctYmI3NmFhMTRjN2Y5","displayName":"Bennie Moneypenny"},"authenticatorSelection":{"userVerification":"preferred"},"timeout":60000}';
        $publicKeyCredentialCreationOptions = $serializer->deserialize(
            $options,
            PublicKeyCredentialCreationOptions::class,
            'json'
        );

        $storage = static::getContainer()->get(CustomSessionStorage::class);
        $storage->store(Item::create(
            $publicKeyCredentialCreationOptions,
            PublicKeyCredentialUserEntity::create('john', 'doe', 'Foo BAR (-_-)')
        ));

        $assertion = '{"id":"WT7a99M1zA3XUBBvEwXqPzP0C3zNoS_SpmMpv2sG2YM","rawId":"WT7a99M1zA3XUBBvEwXqPzP0C3zNoS/SpmMpv2sG2YM","response":{"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZydjc2lnWECRl1RciDxSF7hkhJbqVJeryUIFrX7r6QQMQq8bIP4wYRA6f96iOO4wiOo34l65kZ5v1erxSmIaH56VySUSMusEaGF1dGhEYXRhWIGWBOqCgk6YpK2hS0Ri0Nc6jsRpEw2pGxkwdFkin3SjWUEAAAAykd_q15WeRHWtJpsNSCvgiQAgWT7a99M1zA3XUBBvEwXqPzP0C3zNoS_SpmMpv2sG2YOkAQEDJyAGIVgg4smTlXUJnAP_RqNWNv2Eqkh8I7ZDS0IuSgotbPygd9k","clientDataJSON":"eyJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLnNwb21reS1sYWJzLmNvbSIsImNoYWxsZW5nZSI6IkVoTlZ0M1Q4VjEyRkp2U0FjNTBuaEtuWi1NRWMta2Y4NHhlcERjR3lOMWciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"},"type":"public-key"}';

        $crawler = $client->request(Request::METHOD_GET, '/login');

        // When
        $form = $crawler->selectButton('login')
            ->form();
        $client->submit($form, [
            '_assertion' => $assertion,
        ]);

        // Then
        static::assertResponseIsSuccessful();
        static::assertSame('{"success":true}', $client->getResponse()->getContent());
        static::assertTrue($client->getRequest()->getSession()->has('_security_main'));

        // And then
        $client->request(Request::METHOD_GET, '/admin');
        static::assertResponseStatusCodeSame(403);
    }
}
