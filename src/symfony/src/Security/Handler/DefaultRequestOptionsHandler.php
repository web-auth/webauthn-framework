<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Handler;

use RuntimeException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;
use function is_array;
use const JSON_THROW_ON_ERROR;

final class DefaultRequestOptionsHandler implements RequestOptionsHandler
{
    public function onRequestOptions(
        PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions,
        ?PublicKeyCredentialUserEntity $userEntity
    ): Response {
        $data = json_decode(
            json_encode($publicKeyCredentialRequestOptions, JSON_THROW_ON_ERROR),
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
