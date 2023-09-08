<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Handler;

use RuntimeException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialUserEntity;
use function is_array;
use const JSON_THROW_ON_ERROR;

final class DefaultCreationOptionsHandler implements CreationOptionsHandler
{
    public function onCreationOptions(
        PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        PublicKeyCredentialUserEntity $userEntity
    ): Response {
        $data = json_decode(
            json_encode($publicKeyCredentialCreationOptions, JSON_THROW_ON_ERROR),
            true,
            512,
            JSON_THROW_ON_ERROR
        );
        is_array($data) || throw new RuntimeException('Unable to encode the response to JSON.');
        $data['status'] = 'ok';
        $data['errorMessage'] = '';

        return new JsonResponse($data);
    }
}
