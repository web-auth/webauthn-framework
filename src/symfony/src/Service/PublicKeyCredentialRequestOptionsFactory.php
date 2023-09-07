<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use InvalidArgumentException;
use Psr\EventDispatcher\EventDispatcherInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\Bundle\Event\PublicKeyCredentialRequestOptionsCreatedEvent;
use Webauthn\MetadataService\Event\CanDispatchEvents;
use Webauthn\MetadataService\Event\NullEventDispatcher;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use function array_key_exists;

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
        ?string $userVerification = null,
        ?AuthenticationExtensionsClientInputs $authenticationExtensionsClientInputs = null
    ): PublicKeyCredentialRequestOptions {
        array_key_exists($key, $this->profiles) || throw new InvalidArgumentException(sprintf(
            'The profile with key "%s" does not exist.',
            $key
        ));
        $profile = $this->profiles[$key];

        $options = PublicKeyCredentialRequestOptions::create(random_bytes($profile['challenge_length']));
        $options->rpId = $profile['rp_id'];
        $options->userVerification = $userVerification ?? $profile['user_verification'];
        $options->allowCredentials = $allowCredentials;
        $options->timeout = $profile['timeout'];
        $options->extensions = $authenticationExtensionsClientInputs ?? $this->createExtensions($profile);
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
    private function createExtensions(array $profile): AuthenticationExtensionsClientInputs
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
