<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Handler;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialUserEntity;

final class DefaultCreationOptionsHandler implements CreationOptionsHandler
{
    public function onCreationOptions(PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions, PublicKeyCredentialUserEntity $userEntity): Response
    {
        $data = $publicKeyCredentialCreationOptions->jsonSerialize();
        $data['status'] = 'ok';
        $data['errorMessage'] = '';

        return new JsonResponse($data);
    }
}
