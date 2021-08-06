<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\EntryPoint;

use JetBrains\PhpStorm\Pure;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

final class WebauthnEntryPoint implements AuthenticationEntryPointInterface
{
    #[Pure]
    public function __construct(private AuthenticationFailureHandlerInterface $failureHandler)
    {
    }

    /**
     * {@inheritdoc}
     */
    public function start(Request $request, AuthenticationException $authException = null): Response
    {
        $exception = $authException ?? new AuthenticationException('Authentication Required');

        return $this->failureHandler->onAuthenticationFailure($request, $exception);
    }
}
