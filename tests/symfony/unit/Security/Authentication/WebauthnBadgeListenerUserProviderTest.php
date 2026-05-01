<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Security\Authentication;

use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use RuntimeException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Event\CheckPassportEvent;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepositoryInterface;
use Webauthn\Bundle\Security\Authentication\WebauthnBadge;
use Webauthn\Bundle\Security\Authentication\WebauthnBadgeListener;
use Webauthn\Bundle\Security\Authentication\WebauthnPassport;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;

/**
 * Documents the three user-provider resolution paths that the bundle exposes (issue #833 follow-up).
 *
 * Path 1: badge created with an explicit `userLoader` callback → priority over anything else.
 * Path 2: built-in `webauthn:` firewall → uses the firewall's `provider:` config (covered by a
 *         dedicated integration test on the security factory wiring, see WebauthnFactoryFirewallProviderTest).
 * Path 3: badge created without `userLoader` → listener falls back to the injected
 *         `UserProviderInterface` (currently `security.user_providers`).
 *
 * @internal
 */
final class WebauthnBadgeListenerUserProviderTest extends TestCase
{
    #[Test]
    public function explicitBadgeUserLoaderTakesPriorityOverListenerFallback(): void
    {
        $explicitLoader = static fn (string $identifier): UserInterface => new InMemoryUser('from-badge-loader', null);
        $badge = new WebauthnBadge('localhost', '{}', userLoader: $explicitLoader);

        $listener = $this->createListener(
            $this->failingUserProvider(
                'Listener fallback should not be invoked when the badge already has a user loader.'
            ),
        );

        $listener->checkPassport($this->makeEvent($badge));

        // The listener must leave the explicit loader untouched.
        static::assertSame($explicitLoader, $badge->getUserLoader());
    }

    #[Test]
    public function listenerInstallsUserLoaderFromInjectedProviderWhenBadgeHasNone(): void
    {
        $badge = new WebauthnBadge('localhost', '{}');
        static::assertNull($badge->getUserLoader(), 'Sanity check: badge starts with no user loader.');

        $expectedUser = new InMemoryUser('from-injected-provider', null);
        $listener = $this->createListener($this->capturingUserProvider($expectedUser));

        $listener->checkPassport($this->makeEvent($badge));

        $loader = $badge->getUserLoader();
        static::assertNotNull($loader, 'The listener must install a user loader when none was provided.');
        static::assertSame($expectedUser, $loader('alice'));
    }

    #[Test]
    public function resolvedBadgeIsLeftUntouched(): void
    {
        // Once a badge is resolved, no path is re-applied — the flow is idempotent.
        $sentinelLoader = static fn (string $identifier): UserInterface => new InMemoryUser('sentinel', null);
        $badge = new WebauthnBadge('localhost', '{}', userLoader: $sentinelLoader);
        $this->markBadgeResolved($badge);

        $listener = $this->createListener(
            $this->failingUserProvider('Resolved badges must short-circuit before any provider lookup.'),
        );

        $listener->checkPassport($this->makeEvent($badge));

        static::assertSame($sentinelLoader, $badge->getUserLoader());
    }

    private function createListener(UserProviderInterface $userProvider): WebauthnBadgeListener
    {
        // Stub the deserializer so it throws immediately: the listener catches the exception in its
        // try/catch and returns. The user-provider resolution we test happens BEFORE that try/catch,
        // so the early short-circuit does not affect what we assert.
        $serializer = static::createStub(SerializerInterface::class);
        $serializer->method('deserialize')
            ->willThrowException(new RuntimeException('intentionally short-circuited'));

        return new WebauthnBadgeListener(
            optionsStorage: static::createStub(OptionsStorage::class),
            publicKeyCredentialLoader: $serializer,
            credentialUserEntityRepository: static::createStub(PublicKeyCredentialUserEntityRepositoryInterface::class),
            publicKeyCredentialSourceRepository: static::createStub(CredentialRecordRepositoryInterface::class),
            assertionResponseValidator: AuthenticatorAssertionResponseValidator::create(
                (new CeremonyStepManagerFactory())->requestCeremony()
            ),
            attestationResponseValidator: AuthenticatorAttestationResponseValidator::create(
                (new CeremonyStepManagerFactory())->creationCeremony()
            ),
            userProvider: $userProvider,
        );
    }

    private function makeEvent(WebauthnBadge $badge): CheckPassportEvent
    {
        return new CheckPassportEvent(
            static::createStub(AuthenticatorInterface::class),
            new WebauthnPassport($badge),
        );
    }

    /**
     * Provider that fails the test if its lookup is invoked — used to assert that the listener
     * stays away from its own provider on Path 1 and on the resolved-badge short-circuit.
     */
    private function failingUserProvider(string $message): UserProviderInterface
    {
        return new class($message) implements UserProviderInterface {
            public function __construct(
                private readonly string $message
            ) {
            }

            public function loadUserByIdentifier(string $identifier): UserInterface
            {
                TestCase::fail($this->message);
            }

            public function refreshUser(UserInterface $user): UserInterface
            {
                throw new LogicException('not used');
            }

            public function supportsClass(string $class): bool
            {
                return false;
            }
        };
    }

    /**
     * Provider that returns a fixed user — used on Path 3 to assert the loader installed by the
     * listener actually invokes the injected provider.
     */
    private function capturingUserProvider(UserInterface $user): UserProviderInterface
    {
        return new class($user) implements UserProviderInterface {
            public function __construct(
                private readonly UserInterface $user
            ) {
            }

            public function loadUserByIdentifier(string $identifier): UserInterface
            {
                return $this->user;
            }

            public function refreshUser(UserInterface $user): UserInterface
            {
                throw new UserNotFoundException();
            }

            public function supportsClass(string $class): bool
            {
                return false;
            }
        };
    }

    private function markBadgeResolved(WebauthnBadge $badge): void
    {
        $reflection = new ReflectionProperty(WebauthnBadge::class, 'isResolved');
        $reflection->setValue($badge, true);
    }
}
