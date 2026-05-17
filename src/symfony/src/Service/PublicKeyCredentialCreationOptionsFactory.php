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
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Event\PublicKeyCredentialCreationOptionsCreatedEvent;
use Webauthn\Event\CanDispatchEvents;
use Webauthn\Event\NullEventDispatcher;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

final class PublicKeyCredentialCreationOptionsFactory implements CanDispatchEvents
{
    private EventDispatcherInterface $eventDispatcher;

    /**
     * @param array<string, array{rp: array{name: string, id: ?string}, challenge_length: int, timeout?: ?int, attestation_conveyance?: ?string, authenticator_selection_criteria: array{authenticator_attachment: ?string, user_verification: ?string, resident_key: ?string}, public_key_credential_parameters: list<int>, extensions: array<string, mixed>, conditional_create?: bool}> $profiles
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
        null|AuthenticationExtensions $AuthenticationExtensions = null,
        null|string $mediation = null,
    ): PublicKeyCredentialCreationOptions {
        array_key_exists($key, $this->profiles) || throw new InvalidArgumentException(sprintf(
            'The profile with key "%s" does not exist.',
            $key
        ));
        $profile = $this->profiles[$key];

        $timeout = $profile['timeout'] ?? null;
        $timeout === null || $timeout > 1 || throw new InvalidArgumentException(sprintf(
            'The profile with key "%s" has an invalid timeout value. Expected a positive integer greater than 0, got "%s".',
            $key,
            gettype($timeout)
        ));
        $attestation = $attestationConveyance ?? $profile['attestation_conveyance'] ?? null;

        // The legacy `conditional_create: true` profile flag stays as a shortcut and feeds the new
        // `mediation` mechanism: an explicit per-request mediation always wins, otherwise the profile
        // default applies.
        $effectiveMediation = $mediation
            ?? (($profile['conditional_create'] ?? false) === true
                ? PublicKeyCredentialCreationOptions::MEDIATION_CONDITIONAL
                : null);

        /** @var int<1, max> $challengeLength */
        $challengeLength = $profile['challenge_length'];
        $options = PublicKeyCredentialCreationOptions
            ::create(
                $this->createRpEntity($profile),
                $userEntity,
                random_bytes($challengeLength),
                $this->createCredentialParameters($profile),
                authenticatorSelection: $authenticatorSelection ?? $this->createAuthenticatorSelectionCriteria(
                    $profile
                ),
                attestation: $attestation,
                excludeCredentials: $excludeCredentials,
                timeout: $timeout,
                extensions: $AuthenticationExtensions ?? $this->createExtensions($profile),
                mediation: $effectiveMediation,
            );
        $this->eventDispatcher->dispatch(PublicKeyCredentialCreationOptionsCreatedEvent::create($options));

        return $options;
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

    /**
     * @param array{authenticator_selection_criteria: array{authenticator_attachment: ?string, user_verification: ?string, resident_key: ?string}} $profile
     */
    private function createAuthenticatorSelectionCriteria(array $profile): AuthenticatorSelectionCriteria
    {
        return AuthenticatorSelectionCriteria::create(
            $profile['authenticator_selection_criteria']['authenticator_attachment'],
            $profile['authenticator_selection_criteria']['user_verification'] ?? AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            $profile['authenticator_selection_criteria']['resident_key'],
        );
    }

    /**
     * Per W3C IDL, `PublicKeyCredentialEntity.name` is required. When the deprecated
     * `webauthn.creation_profiles.*.rp.name` node is omitted, the configuration default is an
     * empty string and SimpleWebAuthn's browser bindings refuse to call
     * `navigator.credentials.create()`. Falling back to the `id` (a human-readable hostname)
     * keeps the JSON well-formed for callers that already dropped the deprecated node.
     *
     * @param array{rp: array{name: string, id: ?string}} $profile
     */
    private function createRpEntity(array $profile): PublicKeyCredentialRpEntity
    {
        $name = $profile['rp']['name'];
        if ($name === '') {
            $name = (string) $profile['rp']['id'];
        }

        return PublicKeyCredentialRpEntity::create($name, $profile['rp']['id']);
    }

    /**
     * @param array{public_key_credential_parameters: list<int>} $profile
     *
     * @return PublicKeyCredentialParameters[]
     */
    private function createCredentialParameters(array $profile): array
    {
        $callback = static fn (int $alg): PublicKeyCredentialParameters => PublicKeyCredentialParameters::create(
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $alg
        );

        return array_map($callback, $profile['public_key_credential_parameters']);
    }
}
