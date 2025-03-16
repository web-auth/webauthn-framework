<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Authentication;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Event\CheckPassportEvent;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\SerializerInterface;
use Throwable;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Repository\CanRegisterUserEntity;
use Webauthn\Bundle\Repository\CanSaveCredentialSource;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepositoryInterface;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Exception\InvalidDataException;
use Webauthn\Exception\UnsupportedFeatureException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;

final readonly class WebauthnBadgeListener
{
    public function __construct(
        private OptionsStorage $optionsStorage,
        private SerializerInterface $publicKeyCredentialLoader,
        private PublicKeyCredentialUserEntityRepositoryInterface $credentialUserEntityRepository,
        private PublicKeyCredentialSourceRepositoryInterface $publicKeyCredentialSourceRepository,
        private AuthenticatorAssertionResponseValidator $assertionResponseValidator,
        private AuthenticatorAttestationResponseValidator $attestationResponseValidator,
        private UserProviderInterface $userProvider,
    ) {
    }

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
        } catch (Throwable) {
            return;
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
        if ($this->publicKeyCredentialSourceRepository instanceof CanSaveCredentialSource) {
            $this->publicKeyCredentialSourceRepository->saveCredentialSource($publicKeyCredentialSource);
        }

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
        if (! $this->publicKeyCredentialSourceRepository instanceof CanSaveCredentialSource) {
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
        $this->publicKeyCredentialSourceRepository->saveCredentialSource($publicKeyCredentialSource);

        $badge->markResolved(
            $response,
            $publicKeyCredentialCreationOptions,
            $userEntity,
            $publicKeyCredentialSource,
        );
    }
}
