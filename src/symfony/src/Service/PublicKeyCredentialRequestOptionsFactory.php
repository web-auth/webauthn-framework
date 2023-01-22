<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use function array_key_exists;
use Psr\EventDispatcher\EventDispatcherInterface;
use RuntimeException;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\Bundle\Event\PublicKeyCredentialRequestOptionsCreatedEvent;
use Webauthn\MetadataService\Event\CanDispatchEvents;
use Webauthn\MetadataService\Event\NullEventDispatcher;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;

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
        array_key_exists($key, $this->profiles) || throw new RuntimeException(sprintf(
            'The profile with key "%s" does not exist.',
            $key
        ));
        $profile = $this->profiles[$key];

        $options = PublicKeyCredentialRequestOptions
            ::create(random_bytes($profile['challenge_length']))
                ->setRpId($profile['rp_id'])
                ->setUserVerification($userVerification ?? $profile['user_verification'])
                ->allowCredentials(...$allowCredentials)
                ->setExtensions($authenticationExtensionsClientInputs ?? $this->createExtensions($profile))
                ->setTimeout($profile['timeout']);
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
        $extensions = new AuthenticationExtensionsClientInputs();
        foreach ($profile['extensions'] as $k => $v) {
            $extensions->add(AuthenticationExtension::create($k, $v));
        }

        return $extensions;
    }
}
