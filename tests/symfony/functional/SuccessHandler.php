<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Webauthn\Bundle\Security\Handler\SuccessHandler as SuccessHandlerInterface;

final class SuccessHandler implements AuthenticationSuccessHandlerInterface, SuccessHandlerInterface
{
    public function onSuccess(Request $request): Response
    {
        $data = [
            'status' => 'ok',
            'errorMessage' => '',
        ];

        return new JsonResponse($data, JsonResponse::HTTP_OK);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token): Response
    {
        $data = [
            'status' => 'ok',
            'errorMessage' => '',
            'userIdentifier' => $token->getUserIdentifier(),
        ];

        return new JsonResponse($data, JsonResponse::HTTP_OK);
    }
}
