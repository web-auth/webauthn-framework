<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Handler;

use Symfony\Component\HttpFoundation\Response;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialUserEntity;

interface CreationOptionsHandler
{
    public function onCreationOptions(
        PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        PublicKeyCredentialUserEntity $userEntity
    ): Response;
}
