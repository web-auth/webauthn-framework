<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use Assert\Assertion;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\Bundle\Event\PublicKeyCredentialRequestOptionsCreatedEvent;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;

final class PublicKeyCredentialRequestOptionsFactory
{
    /**
     * @param mixed[] $profiles
     */
    public function __construct(
        private array $profiles,
        private EventDispatcherInterface $eventDispatcher
    ) {
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
        Assertion::keyExists($this->profiles, $key, sprintf('The profile with key "%s" does not exist.', $key));
        $profile = $this->profiles[$key];

        $options = PublicKeyCredentialRequestOptions
            ::create(random_bytes($profile['challenge_length']))
                ->setRpId($profile['rp_id'])
                ->setUserVerification($userVerification ?? $profile['user_verification'])
                ->allowCredentials($allowCredentials)
                ->setExtensions($authenticationExtensionsClientInputs ?? $this->createExtensions($profile))
                ->setTimeout($profile['timeout'])
        ;
        $this->eventDispatcher->dispatch(new PublicKeyCredentialRequestOptionsCreatedEvent($options));

        return $options;
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
