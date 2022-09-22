<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Guesser;

use InvalidArgumentException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\PublicKeyCredentialUserEntity;

final class CurrentUserEntityGuesser implements UserEntityGuesser
{
    public function __construct(
        private readonly TokenStorageInterface $tokenStorage,
        private readonly PublicKeyCredentialUserEntityRepository $userEntityRepository
    ) {
    }

    public function findUserEntity(Request $request): PublicKeyCredentialUserEntity
    {
        $user = $this->tokenStorage->getToken()?->getUser();
        $user !== null || throw new InvalidArgumentException('Unable to find the user entity');
        $userEntity = $this->userEntityRepository->findOneByUsername($user->getUserIdentifier());
        $userEntity !== null || throw new InvalidArgumentException('Unable to find the user entity');

        return $userEntity;
    }
}
