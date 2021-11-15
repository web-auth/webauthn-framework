<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Guesser;

use Symfony\Component\HttpFoundation\Request;
use Webauthn\PublicKeyCredentialUserEntity;

interface UserEntityGuesser
{
    public function findUserEntity(Request $request): PublicKeyCredentialUserEntity;
}
