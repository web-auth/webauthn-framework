<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use InvalidArgumentException;
use Psr\EventDispatcher\EventDispatcherInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\Bundle\Event\PublicKeyCredentialRequestOptionsCreatedEvent;
use Webauthn\Event\CanDispatchEvents;
use Webauthn\Event\NullEventDispatcher;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use function array_key_exists;
use function gettype;
use function is_int;
use function is_string;
use function sprintf;

final class PublicKeyCredentialRequestOptionsFactory implements CanDispatchEvents
{
    private EventDispatcherInterface $eventDispatcher;

    /**
     * @param mixed[] $profiles
     */
    public function __construct(
        private readonly array $profiles,
        ?EventDispatcherInterface $eventDispatcher = null
    ) {
        if ($eventDispatcher === null) {
            $this->eventDispatcher = new NullEventDispatcher();
        } else {
            $this->eventDispatcher = $eventDispatcher;
            trigger_deprecation(
                'web-auth/webauthn-symfony-bundle',
                '4.5.0',
                'The parameter "$eventDispatcher" is deprecated since 4.5.0 will be removed in 5.0.0. Please use `setEventDispatcher` instead.'
            );
        }
    }

    /**
     * @param PublicKeyCredentialDescriptor[] $allowCredentials
     */
    public function create(
        string $key,
        array $allowCredentials,
        null|string $userVerification = null,
        null|AuthenticationExtensions $authenticationExtensionsClientInputs = null
    ): PublicKeyCredentialRequestOptions {
        array_key_exists($key, $this->profiles) || throw new InvalidArgumentException(sprintf(
            'The profile with key "%s" does not exist.',
            $key
        ));
        $profile = $this->profiles[$key];
        $rpId = $profile['rp_id'] ?? null;
        $rpId === null || is_string($rpId) || throw new InvalidArgumentException(sprintf(
            'The profile with key "%s" has an invalid rp_id value. Expected a string or null, got "%s".',
            $key,
            gettype($rpId)
        ));
        $timeout = $profile['timeout'] ?? null;
        $timeout === null || (is_int($timeout) && $timeout > 1) || throw new InvalidArgumentException(sprintf(
            'The profile with key "%s" has an invalid timeout value. Expected a positive integer greater than 0, got "%s".',
            $key,
            gettype($timeout)
        ));
        $userVerification ??= $profile['user_verification'] ?? null;
        $userVerification === null || is_string($userVerification) || throw new InvalidArgumentException(sprintf(
            'The profile with key "%s" has an invalid attestation_conveyance value. Expected a string or null, got "%s".',
            $key,
            gettype($userVerification)
        ));

        $options = PublicKeyCredentialRequestOptions::create(
            random_bytes($profile['challenge_length']),
            rpId: $rpId,
            allowCredentials: $allowCredentials,
            userVerification: $userVerification,
            timeout: $timeout,
            extensions: $authenticationExtensionsClientInputs ?? $this->createExtensions($profile)
        );
        $this->eventDispatcher->dispatch(PublicKeyCredentialRequestOptionsCreatedEvent::create($options));

        return $options;
    }

    public function setEventDispatcher(EventDispatcherInterface $eventDispatcher): void
    {
        $this->eventDispatcher = $eventDispatcher;
    }

    /**
     * @param mixed[] $profile
     */
    private function createExtensions(array $profile): AuthenticationExtensions
    {
        return AuthenticationExtensionsClientInputs::create(
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
