<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Security\Storage;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\Bundle\Security\Storage\SessionStorage;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * @internal
 */
final class SessionStorageTest extends TestCase
{
    private const CHALLENGE = 'challenge';

    #[Test]
    public function theScopeOfTheItemIsKeptInTheSession(): void
    {
        $storage = new SessionStorage($this->requestStack(new Session(new MockArraySessionStorage())));

        $storage->store(Item::create($this->options(), null)->withScope('firewall.main'));

        static::assertSame('firewall.main', $storage->get(self::CHALLENGE)->getScope());
    }

    #[Test]
    public function anItemStoredWithoutScopeComesBackWithoutScope(): void
    {
        $storage = new SessionStorage($this->requestStack(new Session(new MockArraySessionStorage())));

        $storage->store(Item::create($this->options(), null));

        static::assertNull($storage->get(self::CHALLENGE)->getScope());
    }

    /**
     * Sessions opened before the scope existed hold the options and the user entity only.
     */
    #[Test]
    public function aSessionValueWrittenBeforeTheScopeExistedStillLoads(): void
    {
        $session = new Session(new MockArraySessionStorage());
        $session->set($this->sessionKey(), [
            'options' => $this->options(),
            'userEntity' => null,
        ]);
        $storage = new SessionStorage($this->requestStack($session));

        $item = $storage->get(self::CHALLENGE);

        static::assertNull($item->getScope());
        static::assertSame(self::CHALLENGE, $item->getPublicKeyCredentialOptions()->challenge);
    }

    #[Test]
    public function aSessionValueWithAnInvalidScopeIsRejected(): void
    {
        $session = new Session(new MockArraySessionStorage());
        $session->set($this->sessionKey(), [
            'options' => $this->options(),
            'userEntity' => null,
            'scope' => ['firewall.main'],
        ]);
        $storage = new SessionStorage($this->requestStack($session));

        $this->expectException(BadRequestHttpException::class);
        $this->expectExceptionMessage('No valid options scope available for this session.');

        $storage->get(self::CHALLENGE);
    }

    /**
     * A request stack that hands out `$session`. It does not rely on the constructor arguments of {@see RequestStack},
     * which the oldest supported Symfony versions do not have.
     */
    private function requestStack(SessionInterface $session): RequestStack
    {
        return new class($session) extends RequestStack {
            public function __construct(
                private readonly SessionInterface $session
            ) {
            }

            public function getSession(): SessionInterface
            {
                return $this->session;
            }
        };
    }

    private function options(): PublicKeyCredentialRequestOptions
    {
        return PublicKeyCredentialRequestOptions::create(self::CHALLENGE, 'example.com');
    }

    private function sessionKey(): string
    {
        return sprintf('WEBAUTHN_PUBLIC_KEY_OPTIONS-%s', hash('xxh128', self::CHALLENGE));
    }
}
