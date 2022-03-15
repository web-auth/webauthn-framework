<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use ParagonIE\ConstantTime\Base64;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;

final class SuccessHandler implements AuthenticationSuccessHandlerInterface
{
    public function onAuthenticationSuccess(Request $request, TokenInterface $token): JsonResponse
    {
        $data = [
            'status' => 'ok',
            'errorMessage' => '',
            'userId' => Base64::encode($token->getUserIdentifier()),
        ];

        return new JsonResponse($data, JsonResponse::HTTP_OK);
    }
}
