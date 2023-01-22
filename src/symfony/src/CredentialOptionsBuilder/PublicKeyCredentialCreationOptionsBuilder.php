<?php

declare(strict_types=1);

namespace Webauthn\Bundle\CredentialOptionsBuilder;

use Symfony\Component\HttpFoundation\Request;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialUserEntity;

interface PublicKeyCredentialCreationOptionsBuilder
{
    public function getFromRequest(
        Request $request,
        PublicKeyCredentialUserEntity $userEntity
    ): PublicKeyCredentialCreationOptions;
}
