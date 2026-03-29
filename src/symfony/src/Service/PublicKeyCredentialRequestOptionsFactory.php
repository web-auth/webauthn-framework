<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use function array_key_exists;
use function gettype;
use InvalidArgumentException;
use Psr\EventDispatcher\EventDispatcherInterface;
use function sprintf;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\Bundle\Event\PublicKeyCredentialRequestOptionsCreatedEvent;
use Webauthn\Event\CanDispatchEvents;
use Webauthn\Event\NullEventDispatcher;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;

final class PublicKeyCredentialRequestOptionsFactory implements CanDispatchEvents
{
    private EventDispatcherInterface $eventDispatcher;

    /**
     * @param array<string, array{challenge_length: int, rp_id?: ?string, timeout?: ?int, user_verification?: ?string, extensions: array<string, mixed>}> $profiles
     */
    public function __construct(
        private readonly array $profiles,
    ) {
        $this->eventDispatcher = new NullEventDispatcher();
    }

    /**
     * @param PublicKeyCredentialDescriptor[] $allowCredentials
     */
    public function create(
        string $key,
        array $allowCredentials,
        null|string $userVerification = null,
        null|AuthenticationExtensions $AuthenticationExtensions = null
    ): PublicKeyCredentialRequestOptions {
        array_key_exists($key, $this->profiles) || throw new InvalidArgumentException(sprintf(
            'The profile with key "%s" does not exist.',
            $key
        ));
        $profile = $this->profiles[$key];
        $rpId = $profile['rp_id'] ?? null;
        $timeout = $profile['timeout'] ?? null;
        $timeout === null || $timeout > 1 || throw new InvalidArgumentException(sprintf(
            'The profile with key "%s" has an invalid timeout value. Expected a positive integer greater than 0, got "%s".',
            $key,
            gettype($timeout)
        ));
        $userVerification ??= $profile['user_verification'] ?? null;

        /** @var int<1, max> $challengeLength */
        $challengeLength = $profile['challenge_length'];
        $options = PublicKeyCredentialRequestOptions::create(
            random_bytes($challengeLength),
            rpId: $rpId,
            allowCredentials: $allowCredentials,
            userVerification: $userVerification,
            timeout: $timeout,
            extensions: $AuthenticationExtensions ?? $this->createExtensions($profile)
        );
        $this->eventDispatcher->dispatch(PublicKeyCredentialRequestOptionsCreatedEvent::create($options));

        return $options;
    }

    public function setEventDispatcher(EventDispatcherInterface $eventDispatcher): void
    {
        $this->eventDispatcher = $eventDispatcher;
    }

    /**
     * @param array{extensions: array<string, mixed>} $profile
     */
    private function createExtensions(array $profile): AuthenticationExtensions
    {
        return AuthenticationExtensions::create(
            array_map(
                static fn (string $name, mixed $value): AuthenticationExtension => AuthenticationExtension::create(
                    $name,
                    $value
                ),
                array_keys($profile['extensions']),
                $profile['extensions']
            )
        );
    }
}
