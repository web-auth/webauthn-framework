<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Assertion;

use const JSON_THROW_ON_ERROR;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Component\HttpFoundation\Request;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepositoryInterface;
use Webauthn\CredentialRecord;
use Webauthn\FakeCredentialGenerator;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\Bundle\Functional\PublicKeyCredentialUserEntityRepository;
use Webauthn\Tests\Bundle\Functional\WebauthnTestCase;

/**
 * Security non-regression for GHSA-pm4w-cq4x-rv8q: an account without any registered credential got an empty
 * allowCredentials list while an unknown username got decoys, so a single assertion options request revealed that the
 * account exists. Such an account now gets the decoys of the fake credential generator, on the firewall and on the
 * request controllers alike.
 *
 * @internal
 */
final class UsernameEnumerationTest extends WebauthnTestCase
{
    /**
     * @return iterable<string, array{string, string}>
     */
    public static function optionsPaths(): iterable
    {
        yield 'firewall' => ['/api/login/options', 'test.com'];
        yield 'request controller' => ['/devices/test/options', 'localhost'];
    }

    #[Test]
    #[DataProvider('optionsPaths')]
    public function anAccountWithoutCredentialsGetsTheDecoysOfTheFakeCredentialGenerator(
        string $path,
        string $host
    ): void {
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->disableReboot();
        static::getContainer()->get(PublicKeyCredentialUserEntityRepository::class)->saveUserEntity(
            PublicKeyCredentialUserEntity::create('no-credential-user', 'no-credential-user-id', 'No Credential')
        );
        $decoys = static::getContainer()->get(FakeCredentialGenerator::class)->generate(
            Request::create($path, Request::METHOD_POST),
            'no-credential-user'
        );

        static::assertNotSame([], $decoys);
        static::assertSame(
            array_map(static fn (PublicKeyCredentialDescriptor $descriptor): string => $descriptor->id, $decoys),
            $this->requestAllowedCredentialIds($client, $path, $host, 'no-credential-user')
        );
    }

    #[Test]
    #[DataProvider('optionsPaths')]
    public function aRegisteredAccountGetsItsOwnCredentials(string $path, string $host): void
    {
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->disableReboot();
        $userEntity = static::getContainer()->get(PublicKeyCredentialUserEntityRepositoryInterface::class)
            ->findOneByUsername('admin');
        static::assertNotNull($userEntity);
        $credentialIds = array_map(
            static fn (CredentialRecord $credential): string => $credential->publicKeyCredentialId,
            static::getContainer()->get(CredentialRecordRepositoryInterface::class)->findAllForUserEntity($userEntity)
        );

        static::assertNotSame([], $credentialIds);
        static::assertSame($credentialIds, $this->requestAllowedCredentialIds($client, $path, $host, 'admin'));
    }

    /**
     * @return string[]
     */
    private function requestAllowedCredentialIds(
        KernelBrowser $client,
        string $path,
        string $host,
        string $username
    ): array {
        $client->request(Request::METHOD_POST, $path, [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => $host,
            'HTTPS' => 'on',
        ], json_encode([
            'username' => $username,
        ], JSON_THROW_ON_ERROR));

        static::assertResponseIsSuccessful();
        $json = json_decode((string) $client->getResponse()->getContent(), true, 512, JSON_THROW_ON_ERROR);
        static::assertArrayHasKey('allowCredentials', $json);

        return array_map(
            static fn (array $descriptor): string => Base64UrlSafe::decode($descriptor['id']),
            $json['allowCredentials']
        );
    }
}
