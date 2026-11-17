<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Assertion;

use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Component\HttpFoundation\Request;
use Webauthn\Tests\Bundle\Functional\OptionsScopeAppKernel;
use Webauthn\Tests\Bundle\Functional\PublicKeyCredentialSourceRepository;
use Webauthn\Tests\Bundle\Functional\WebauthnTestCase;

/**
 * A challenge issued by one endpoint, and therefore built from its profile, cannot be redeemed at the result endpoint
 * of another one (GHSA-g9ff-w9h6-7ff3).
 *
 * The firewall and the request controller `step_up` require user verification, the request controller `lax` only
 * prefers it (see `config-options-scope.yml`). The security key of the fixture user `admin` (user handle `foo`) is held
 * by someone who does not know its PIN, so its assertions only carry the user presence flag unless stated otherwise.
 *
 * @internal
 */
final class OptionsScopeTest extends WebauthnTestCase
{
    private const ORIGIN = 'https://localhost';

    #[Test]
    public function aRequestControllerRefusesAChallengeIssuedByAnotherRequestController(): void
    {
        $client = $this->createHttpsClient();
        $securityKey = $this->registerSecurityKeyOfAdmin();

        $challenge = $this->fetchChallenge($client, '/lax/options');
        $this->postJson($client, '/step-up', $securityKey->getAssertion($challenge, self::ORIGIN, false));

        static::assertResponseStatusCodeSame(400);
        static::assertSame(
            '{"status":"error","errorMessage":"The options were not issued by this endpoint."}',
            $client->getResponse()
                ->getContent()
        );
    }

    #[Test]
    public function aRequestControllerRefusesAChallengeIssuedByTheFirewall(): void
    {
        $client = $this->createHttpsClient();
        $securityKey = $this->registerSecurityKeyOfAdmin();

        $challenge = $this->fetchChallenge($client, '/api/login/options');
        $this->postJson($client, '/lax', $securityKey->getAssertion($challenge, self::ORIGIN, true));

        static::assertResponseStatusCodeSame(400);
        static::assertSame(
            '{"status":"error","errorMessage":"The options were not issued by this endpoint."}',
            $client->getResponse()
                ->getContent()
        );
    }

    #[Test]
    public function theFirewallRefusesAChallengeIssuedByARequestController(): void
    {
        $client = $this->createHttpsClient();
        $securityKey = $this->registerSecurityKeyOfAdmin();

        $challenge = $this->fetchChallenge($client, '/lax/options');
        $this->postJson($client, '/api/login', $securityKey->getAssertion($challenge, self::ORIGIN, false));

        static::assertResponseStatusCodeSame(401);
        static::assertSame(
            '{"status":"error","errorMessage":"The options were not issued by this firewall."}',
            $client->getResponse()
                ->getContent()
        );
    }

    #[Test]
    public function aRequestControllerStillRequiresUserVerificationOnItsOwnChallenge(): void
    {
        $client = $this->createHttpsClient();
        $securityKey = $this->registerSecurityKeyOfAdmin();

        $challenge = $this->fetchChallenge($client, '/step-up/options');
        $this->postJson($client, '/step-up', $securityKey->getAssertion($challenge, self::ORIGIN, false));

        static::assertResponseStatusCodeSame(400);
        static::assertSame(
            '{"status":"error","errorMessage":"User authentication required."}',
            $client->getResponse()
                ->getContent()
        );
    }

    #[Test]
    public function aRequestControllerAcceptsAVerifiedAssertionOnItsOwnChallenge(): void
    {
        $client = $this->createHttpsClient();
        $securityKey = $this->registerSecurityKeyOfAdmin();

        $challenge = $this->fetchChallenge($client, '/step-up/options');
        $this->postJson($client, '/step-up', $securityKey->getAssertion($challenge, self::ORIGIN, true));

        static::assertResponseStatusCodeSame(201);
        static::assertSame('{"status":"ok","errorMessage":""}', $client->getResponse()->getContent());
    }

    #[Test]
    public function theFirewallAcceptsAVerifiedAssertionOnItsOwnChallenge(): void
    {
        $client = $this->createHttpsClient();
        $securityKey = $this->registerSecurityKeyOfAdmin();

        $challenge = $this->fetchChallenge($client, '/api/login/options');
        $this->postJson($client, '/api/login', $securityKey->getAssertion($challenge, self::ORIGIN, true));

        static::assertResponseIsSuccessful();
        static::assertSame(
            '{"status":"ok","errorMessage":"","userIdentifier":"admin"}',
            $client->getResponse()
                ->getContent()
        );
    }

    protected static function getKernelClass(): string
    {
        return OptionsScopeAppKernel::class;
    }

    private function createHttpsClient(): KernelBrowser
    {
        return static::createClient([], [
            'HTTPS' => 'on',
        ]);
    }

    private function registerSecurityKeyOfAdmin(): SecurityKey
    {
        $securityKey = new SecurityKey('localhost');
        static::getContainer()->get(PublicKeyCredentialSourceRepository::class)
            ->saveCredentialSource($securityKey->credentialRecordFor('foo'));

        return $securityKey;
    }

    private function fetchChallenge(KernelBrowser $client, string $optionsPath): string
    {
        $this->postJson($client, $optionsPath, '{"username":"admin"}');
        static::assertResponseIsSuccessful();
        $options = json_decode((string) $client->getResponse()->getContent(), true, 512, JSON_THROW_ON_ERROR);
        static::assertIsArray($options);
        static::assertIsString($options['challenge'] ?? null);

        return $options['challenge'];
    }

    private function postJson(KernelBrowser $client, string $path, string $body): void
    {
        $client->request(Request::METHOD_POST, $path, [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'localhost',
            'HTTPS' => 'on',
        ], $body);
    }
}
