<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use InvalidArgumentException;
use Psr\EventDispatcher\EventDispatcherInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Event\PublicKeyCredentialCreationOptionsCreatedEvent;
use Webauthn\Event\CanDispatchEvents;
use Webauthn\Event\NullEventDispatcher;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use function array_key_exists;
use function gettype;
use function is_int;
use function is_string;
use function sprintf;

final class PublicKeyCredentialCreationOptionsFactory implements CanDispatchEvents
{
    private EventDispatcherInterface $eventDispatcher;

    /**
     * @param mixed[] $profiles
     */
    public function __construct(
        private readonly array $profiles,
    ) {
        $this->eventDispatcher = new NullEventDispatcher();
    }

    public function setEventDispatcher(EventDispatcherInterface $eventDispatcher): void
    {
        $this->eventDispatcher = $eventDispatcher;
    }

    /**
     * @param PublicKeyCredentialDescriptor[] $excludeCredentials
     */
    public function create(
        string $key,
        PublicKeyCredentialUserEntity $userEntity,
        array $excludeCredentials = [],
        null|AuthenticatorSelectionCriteria $authenticatorSelection = null,
        null|string $attestationConveyance = null,
        null|AuthenticationExtensions $AuthenticationExtensions = null
    ): PublicKeyCredentialCreationOptions {
        array_key_exists($key, $this->profiles) || throw new InvalidArgumentException(sprintf(
            'The profile with key "%s" does not exist.',
            $key
        ));
        $profile = $this->profiles[$key];

        $timeout = $profile['timeout'] ?? null;
        $timeout === null || (is_int($timeout) && $timeout > 1) || throw new InvalidArgumentException(sprintf(
            'The profile with key "%s" has an invalid timeout value. Expected a positive integer greater than 0, got "%s".',
            $key,
            gettype($timeout)
        ));
        $attestation = $attestationConveyance ?? $profile['attestation_conveyance'] ?? null;
        $attestation === null || is_string($attestation) || throw new InvalidArgumentException(sprintf(
            'The profile with key "%s" has an invalid attestation_conveyance value. Expected a string or null, got "%s".',
            $key,
            gettype($attestation)
        ));

        $options = PublicKeyCredentialCreationOptions
            ::create(
                $this->createRpEntity($profile),
                $userEntity,
                random_bytes($profile['challenge_length']),
                $this->createCredentialParameters($profile),
                authenticatorSelection: $authenticatorSelection ?? $this->createAuthenticatorSelectionCriteria(
                    $profile
                ),
                attestation: $attestation,
                excludeCredentials: $excludeCredentials,
                timeout: $timeout,
                extensions: $AuthenticationExtensions ?? $this->createExtensions($profile)
            );
        $this->eventDispatcher->dispatch(PublicKeyCredentialCreationOptionsCreatedEvent::create($options));

        return $options;
    }

    /**
     * @param mixed[] $profile
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

    /**
     * @param mixed[] $profile
     */
    private function createAuthenticatorSelectionCriteria(array $profile): AuthenticatorSelectionCriteria
    {
        return AuthenticatorSelectionCriteria::create(
            $profile['authenticator_selection_criteria']['authenticator_attachment'],
            $profile['authenticator_selection_criteria']['user_verification'],
            $profile['authenticator_selection_criteria']['resident_key'],
        );
    }

    /**
     * @param mixed[] $profile
     */
    private function createRpEntity(array $profile): PublicKeyCredentialRpEntity
    {
        return PublicKeyCredentialRpEntity::create(
            $profile['rp']['name'],
            $profile['rp']['id'],
            $profile['rp']['icon']
        );
    }

    /**
     * @param mixed[] $profile
     *
     * @return PublicKeyCredentialParameters[]
     */
    private function createCredentialParameters(array $profile): array
    {
        $callback = static fn ($alg): PublicKeyCredentialParameters => PublicKeyCredentialParameters::create(
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $alg
        );

        return array_map($callback, $profile['public_key_credential_parameters']);
    }
}
