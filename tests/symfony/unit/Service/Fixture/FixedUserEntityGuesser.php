<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Service\Fixture;

use Symfony\Component\HttpFoundation\Request;
use Webauthn\Bundle\Security\Guesser\UserEntityGuesser;
use Webauthn\PublicKeyCredentialUserEntity;

final readonly class FixedUserEntityGuesser implements UserEntityGuesser
{
    public function __construct(
        private PublicKeyCredentialUserEntity $userEntity,
    ) {
    }

    public function findUserEntity(Request $request): PublicKeyCredentialUserEntity
    {
        return $this->userEntity;
    }
}
