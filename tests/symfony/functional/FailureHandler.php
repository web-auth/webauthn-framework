<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Throwable;
use Webauthn\Bundle\Security\Handler\FailureHandler as FailureHandlerInterface;

final class FailureHandler implements AuthenticationFailureHandlerInterface, FailureHandlerInterface
{
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        return $this->onFailure($request, $exception);
    }

    public function onFailure(Request $request, ?Throwable $exception = null): Response
    {
        $data = [
            'status' => 'error',
            'errorMessage' => $exception->getMessage(),
        ];

        return new JsonResponse($data, $exception->getCode() ?: Response::HTTP_UNAUTHORIZED);
    }
}
