<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Handler;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialUserEntity;

final class DefaultSuccessHandler implements SuccessHandler, AuthenticationSuccessHandlerInterface
{
    public function onSuccess(
        Request $request,
        ?PublicKeyCredential $publicKeyCredential = null,
        ?PublicKeyCredentialOptions $publicKeyCredentialOptions = null,
        ?PublicKeyCredentialUserEntity $userEntity = null
    ): Response {
        $data = [
            'status' => 'ok',
            'errorMessage' => '',
        ];
        $statusCode = $request->getMethod() === Request::METHOD_POST ? Response::HTTP_CREATED : Response::HTTP_OK;

        return new JsonResponse($data, $statusCode);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token): Response
    {
        return $this->onSuccess($request);
    }
}
