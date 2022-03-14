<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Guesser;

use Assert\Assertion;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Security;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\PublicKeyCredentialUserEntity;

final class CurrentUserEntityGuesser implements UserEntityGuesser
{
    public function __construct(
        private Security $security,
        private PublicKeyCredentialUserEntityRepository $userEntityRepository
    ) {
    }

    public function findUserEntity(Request $request): PublicKeyCredentialUserEntity
    {
        $user = $this->security->getUser();
        Assertion::notNull($user, 'Unable to find the user entity');
        $userEntity = $this->userEntityRepository->findOneByUserHandle($user->getUserIdentifier());
        Assertion::notNull($userEntity, 'Unable to find the user entity');

        return $userEntity;
    }
}
