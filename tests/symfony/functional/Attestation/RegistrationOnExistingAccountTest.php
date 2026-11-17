<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Attestation;

use function bin2hex;
use function json_decode;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use function random_bytes;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Component\HttpFoundation\Request;
use Webauthn\Tests\Bundle\Functional\CreationControllersKernel;
use Webauthn\Tests\Bundle\Functional\PublicKeyCredentialSourceRepository;
use Webauthn\Tests\Bundle\Functional\WebauthnTestCase;

/**
 * Registration options requested for a username that is already taken must not let their holder register a credential
 * on that account. The fixture user `admin` has the user handle `foo`: the attacker only knows its username and holds a
 * software passkey of their own.
 *
 * @internal
 */
final class RegistrationOnExistingAccountTest extends WebauthnTestCase
{
    /**
     * A signed-in user redeems, at the creation controller that adds a credential to the current account, the options
     * the firewall issued for `admin`: the storage finds options by their challenge, whichever endpoint issued them.
     */
    #[Test]
    public function aSignedInUserCannotAddACredentialToAnotherAccount(): void
    {
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $ownOptions = $this->post($client, '/api/register/options', json_encode([
            'username' => 'mallory-' . bin2hex(random_bytes(4)),
        ], JSON_THROW_ON_ERROR));
        $ownAccount = $this->post(
            $client,
            '/api/register',
            (new SoftwarePasskey())->attestation($ownOptions['challenge'])
        );
        static::assertSame('ok', $ownAccount['status']);

        $passkey = new SoftwarePasskey();
        $options = $this->post($client, '/api/register/options', '{"username":"admin","displayName":"Not Admin"}');
        $this->post($client, '/devices/add/passkey', $passkey->attestation($options['challenge']));

        static::assertNotSame(Base64UrlSafe::encodeUnpadded('foo'), $options['user']['id']);
        static::assertNotSame('foo', $this->storedUserHandle($passkey));
    }

    /**
     * A visitor uses a creation controller that guesses the user from the request body.
     */
    #[Test]
    public function aVisitorCannotAddACredentialToAnExistingAccount(): void
    {
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);

        $passkey = new SoftwarePasskey();
        $options = $this->post($client, '/signup/options', '{"username":"admin","displayName":"Not Admin"}');
        $this->post($client, '/signup', $passkey->attestation($options['challenge']));

        static::assertNotSame(Base64UrlSafe::encodeUnpadded('foo'), $options['user']['id']);
        static::assertNotSame('foo', $this->storedUserHandle($passkey));
    }

    protected static function getKernelClass(): string
    {
        return CreationControllersKernel::class;
    }

    private function storedUserHandle(SoftwarePasskey $passkey): ?string
    {
        return static::getContainer()->get(PublicKeyCredentialSourceRepository::class)
            ->findOneByCredentialId($passkey->credentialId)?->userHandle;
    }

    /**
     * @return array<string, mixed>
     */
    private function post(KernelBrowser $client, string $path, string $body): array
    {
        $client->request(Request::METHOD_POST, $path, [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'localhost',
        ], $body);

        return json_decode((string) $client->getResponse()->getContent(), true, 512, JSON_THROW_ON_ERROR);
    }
}
