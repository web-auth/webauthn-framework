<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2021 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Security\EntryPoint;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

final class WebauthnEntryPoint implements AuthenticationEntryPointInterface
{
    /**
     * @var AuthenticationFailureHandlerInterface
     */
    private $failureHandler;

    public function __construct(AuthenticationFailureHandlerInterface $failureHandler)
    {
        $this->failureHandler = $failureHandler;
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
