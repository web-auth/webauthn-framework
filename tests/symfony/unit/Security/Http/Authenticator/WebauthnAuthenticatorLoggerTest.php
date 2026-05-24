<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Security\Http\Authenticator;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Stringable;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepositoryInterface;
use Webauthn\Bundle\Security\Http\Authenticator\WebauthnAuthenticator;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Security\WebauthnFirewallConfig;

/**
 * GHSA-q683-8468-r6h6: WebauthnAuthenticator must never include the raw Symfony Request object in
 * its log context. Request::__toString() returns the full HTTP message (headers included), and most
 * Monolog formatters normalise the context array, which would otherwise leak the Cookie and
 * Authorization headers to downstream log sinks.
 *
 * @internal
 */
final class WebauthnAuthenticatorLoggerTest extends TestCase
{
    #[Test]
    public function successLogContextDoesNotIncludeTheRequestObject(): void
    {
        // Given an authenticator wired to an in-memory PSR-3 logger
        $logger = new InMemoryLogger();
        $authenticator = $this->createAuthenticator();
        $authenticator->setLogger($logger);

        // When the success hook fires for an authenticated request
        $authenticator->onAuthenticationSuccess(
            Request::create('/login/result', 'POST'),
            $this->stubToken('alice'),
            'webauthn_firewall'
        );

        // Then the log context exposes safe metadata only, never the raw Request object
        $record = $logger->records[0] ?? null;
        static::assertNotNull($record, 'A log record was expected.');
        $context = $record['context'];
        static::assertArrayNotHasKey('request', $context);
        static::assertSame('/login/result', $context['path']);
        static::assertSame('POST', $context['method']);
        static::assertSame('webauthn_firewall', $context['firewallName']);
        static::assertSame('alice', $context['identifier']);
    }

    #[Test]
    public function failureLogContextDoesNotIncludeTheRequestObject(): void
    {
        // Given an authenticator wired to an in-memory PSR-3 logger
        $logger = new InMemoryLogger();
        $authenticator = $this->createAuthenticator();
        $authenticator->setLogger($logger);

        // When the failure hook fires for a rejected request
        $authenticator->onAuthenticationFailure(
            Request::create('/login/result', 'POST'),
            new AuthenticationException('bad credentials')
        );

        // Then the log context exposes safe metadata plus the exception, never the raw Request object
        $record = $logger->records[0] ?? null;
        static::assertNotNull($record, 'A log record was expected.');
        $context = $record['context'];
        static::assertArrayNotHasKey('request', $context);
        static::assertSame('/login/result', $context['path']);
        static::assertSame('POST', $context['method']);
        static::assertInstanceOf(AuthenticationException::class, $context['exception']);
    }

    #[Test]
    public function successLogContextNeverCarriesSensitiveHeaders(): void
    {
        // Given an authenticator and a Request that carries sensitive headers
        $logger = new InMemoryLogger();
        $authenticator = $this->createAuthenticator();
        $authenticator->setLogger($logger);

        $request = Request::create('/login/result', 'POST');
        $request->headers->set('Cookie', 'PHPSESSID=top-secret');
        $request->headers->set('Authorization', 'Bearer top-secret');

        // When the success hook fires for that Request
        $authenticator->onAuthenticationSuccess($request, $this->stubToken('alice'), 'webauthn_firewall');

        // Then no header value, header name or stringified Request can be observed in the captured records
        $serialised = print_r($logger->records, true);
        static::assertStringNotContainsString('top-secret', $serialised);
        static::assertStringNotContainsString('PHPSESSID', $serialised);
        static::assertStringNotContainsString('Authorization', $serialised);
    }

    private function createAuthenticator(): WebauthnAuthenticator
    {
        $successHandler = static::createStub(AuthenticationSuccessHandlerInterface::class);
        $successHandler->method('onAuthenticationSuccess')
            ->willReturn(new Response());
        $failureHandler = static::createStub(AuthenticationFailureHandlerInterface::class);
        $failureHandler->method('onAuthenticationFailure')
            ->willReturn(new Response());

        return new WebauthnAuthenticator(
            new WebauthnFirewallConfig([], 'webauthn_firewall', new HttpUtils()),
            static::createStub(UserProviderInterface::class),
            $successHandler,
            $failureHandler,
            static::createStub(OptionsStorage::class),
            static::createStub(CredentialRecordRepositoryInterface::class),
            static::createStub(PublicKeyCredentialUserEntityRepositoryInterface::class),
            static::createStub(SerializerInterface::class),
            static::createStub(AuthenticatorAssertionResponseValidator::class),
            static::createStub(AuthenticatorAttestationResponseValidator::class),
        );
    }

    private function stubToken(string $identifier): TokenInterface
    {
        $token = static::createStub(TokenInterface::class);
        $token->method('getUserIdentifier')
            ->willReturn($identifier);

        return $token;
    }
}

/**
 * Minimal in-memory PSR-3 logger used to capture records and assert on their context.
 */
final class InMemoryLogger extends AbstractLogger
{
    /**
     * @var list<array{level: mixed, message: string|Stringable, context: array<string, mixed>}>
     */
    public array $records = [];

    public function log($level, string|Stringable $message, array $context = []): void
    {
        $this->records[] = [
            'level' => $level,
            'message' => $message,
            'context' => $context,
        ];
    }
}
