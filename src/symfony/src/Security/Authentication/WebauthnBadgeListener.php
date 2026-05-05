<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Authentication;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Event\CheckPassportEvent;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\SerializerInterface;
use Throwable;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorResponse;
use Webauthn\Bundle\Repository\CanRegisterUserEntity;
use Webauthn\Bundle\Repository\CanSaveCredentialRecord;
use Webauthn\Bundle\Repository\CanSaveCredentialSource;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepositoryInterface;
use Webauthn\Bundle\Security\Authentication\Exception\WebauthnAuthenticationFailureException;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\CredentialRecord;
use Webauthn\Exception\InvalidDataException;
use Webauthn\Exception\UnsupportedFeatureException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;

final readonly class WebauthnBadgeListener
{
    /**
     * @param UserProviderInterface<UserInterface> $userProvider
     */
    public function __construct(
        private OptionsStorage $optionsStorage,
        private SerializerInterface $publicKeyCredentialLoader,
        private PublicKeyCredentialUserEntityRepositoryInterface $credentialUserEntityRepository,
        private CredentialRecordRepositoryInterface $publicKeyCredentialSourceRepository,
        private AuthenticatorAssertionResponseValidator $assertionResponseValidator,
        private AuthenticatorAttestationResponseValidator $attestationResponseValidator,
        private UserProviderInterface $userProvider,
    ) {
    }

    /**
     * The pre-deserialization phase keeps the historical silent-fail behaviour
     * so other authenticators on the same firewall stay free to handle a
     * request that turns out not to be a WebAuthn ceremony.
     *
     * Once we know the badge IS a WebAuthn ceremony, validation failures are
     * surfaced through {@see WebauthnAuthenticationFailureException}, which
     * carries the deserialized credential and options so an Authenticator's
     * `onAuthenticationFailure()` can build a contextual response (e.g. a W3C
     * §5.1.10 `signalUnknownCredential` payload).
     */
    #[AsEventListener(priority: 512)]
    public function checkPassport(CheckPassportEvent $event): void
    {
        $passport = $event->getPassport();
        if (! $passport->hasBadge(WebauthnBadge::class)) {
            return;
        }

        /** @var WebauthnBadge $badge */
        $badge = $passport->getBadge(WebauthnBadge::class);
        if ($badge->isResolved()) {
            return;
        }
        if ($badge->getUserLoader() === null) {
            $badge->setUserLoader($this->userProvider->loadUserByIdentifier(...));
        }

        try {
            $publicKeyCredential = $this->publicKeyCredentialLoader->deserialize(
                $badge->response,
                PublicKeyCredential::class,
                JsonEncoder::FORMAT
            );
            $response = $publicKeyCredential->response;
            $data = $this->optionsStorage->get($response->clientDataJSON->challenge);
            $publicKeyCredentialRequestOptions = $data->getPublicKeyCredentialOptions();
            $userEntity = $data->getPublicKeyCredentialUserEntity();
        } catch (Throwable) {
            return;
        }

        try {
            switch (true) {
                case $publicKeyCredentialRequestOptions instanceof PublicKeyCredentialRequestOptions && $response instanceof AuthenticatorAssertionResponse:
                    $this->processRequest(
                        $badge,
                        $publicKeyCredentialRequestOptions,
                        $userEntity,
                        $publicKeyCredential->rawId,
                        $response,
                    );
                    break;
                case $badge->allowRegistration && $publicKeyCredentialRequestOptions instanceof PublicKeyCredentialCreationOptions && $response instanceof AuthenticatorAttestationResponse:
                    $this->processCreation($badge, $publicKeyCredentialRequestOptions, $userEntity, $response);
                    break;
                default:
                    return;
            }
        } catch (WebauthnAuthenticationFailureException $exception) {
            throw $exception;
        } catch (Throwable $throwable) {
            throw new WebauthnAuthenticationFailureException(
                $throwable->getMessage(),
                publicKeyCredential: $publicKeyCredential,
                authenticatorResponse: $response instanceof AuthenticatorResponse ? $response : null,
                publicKeyCredentialOptions: $publicKeyCredentialRequestOptions,
                userEntity: $userEntity,
                previous: $throwable,
            );
        }
    }

    private function processRequest(
        WebauthnBadge $badge,
        PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions,
        ?PublicKeyCredentialUserEntity $userEntity,
        string $publicKeyCredentialId,
        AuthenticatorAssertionResponse $response,
    ): void {
        $publicKeyCredentialSource = $this->publicKeyCredentialSourceRepository->findOneByCredentialId(
            $publicKeyCredentialId
        );
        if ($publicKeyCredentialSource === null) {
            throw InvalidDataException::create($publicKeyCredentialSource, 'The credential ID is invalid.');
        }
        $publicKeyCredentialSource = $this->assertionResponseValidator->check(
            $publicKeyCredentialSource,
            $response,
            $publicKeyCredentialRequestOptions,
            $badge->host,
            $userEntity?->id
        );
        $userEntity = $this->credentialUserEntityRepository->findOneByUserHandle(
            $publicKeyCredentialSource->userHandle
        );
        if (! $userEntity instanceof PublicKeyCredentialUserEntity) {
            throw InvalidDataException::create($userEntity, 'Invalid user entity');
        }
        $this->saveCredential($publicKeyCredentialSource);

        $badge->markResolved(
            $response,
            $publicKeyCredentialRequestOptions,
            $userEntity,
            $publicKeyCredentialSource,
        );
    }

    private function processCreation(
        WebauthnBadge $badge,
        PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        ?PublicKeyCredentialUserEntity $userEntity,
        AuthenticatorAttestationResponse $response,
    ): void {
        if (! $this->credentialUserEntityRepository instanceof CanRegisterUserEntity) {
            throw UnsupportedFeatureException::create('The user entity repository does not support registration.');
        }
        if (! $this->publicKeyCredentialSourceRepository instanceof CanSaveCredentialRecord
            && ! $this->publicKeyCredentialSourceRepository instanceof CanSaveCredentialSource) {
            throw UnsupportedFeatureException::create(
                'The credential source repository does not support registration.'
            );
        }
        if (! $userEntity instanceof PublicKeyCredentialUserEntity) {
            return;
        }
        if ($this->credentialUserEntityRepository->findOneByUsername($userEntity->name) !== null) {
            throw InvalidDataException::create($userEntity, 'The username already exists');
        }
        $publicKeyCredentialSource = $this->attestationResponseValidator->check(
            $response,
            $publicKeyCredentialCreationOptions,
            $badge->host,
        );
        if ($this->publicKeyCredentialSourceRepository->findOneByCredentialId(
            $publicKeyCredentialSource->publicKeyCredentialId
        ) !== null) {
            throw InvalidDataException::create($publicKeyCredentialSource, 'The credentials already exists');
        }
        $this->credentialUserEntityRepository->saveUserEntity($userEntity);
        $this->saveCredential($publicKeyCredentialSource);

        $badge->markResolved(
            $response,
            $publicKeyCredentialCreationOptions,
            $userEntity,
            $publicKeyCredentialSource,
        );
    }

    private function saveCredential(CredentialRecord $credentialRecord): void
    {
        if ($this->publicKeyCredentialSourceRepository instanceof CanSaveCredentialRecord) {
            $this->publicKeyCredentialSourceRepository->saveCredentialRecord($credentialRecord);
            return;
        }
        if ($this->publicKeyCredentialSourceRepository instanceof CanSaveCredentialSource) {
            $this->publicKeyCredentialSourceRepository->saveCredentialSource(
                PublicKeyCredentialSource::fromCredentialRecord($credentialRecord)
            );
        }
    }
}
