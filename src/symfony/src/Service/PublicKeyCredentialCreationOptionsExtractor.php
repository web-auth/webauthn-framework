<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use Symfony\Component\HttpFoundation\Request;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialUserEntity;

interface PublicKeyCredentialCreationOptionsExtractor
{
    public function getFromRequest(
        Request $request,
        PublicKeyCredentialUserEntity $userEntity
    ): PublicKeyCredentialCreationOptions;
}
