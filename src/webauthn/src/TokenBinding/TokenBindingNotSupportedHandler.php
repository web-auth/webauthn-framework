<?php

declare(strict_types=1);

namespace Webauthn\TokenBinding;

use Assert\Assertion;
use Psr\Http\Message\ServerRequestInterface;

final class TokenBindingNotSupportedHandler implements TokenBindingHandler
{

    public static function create(): self
    {
        return new self();
    }

    public function check(TokenBinding $tokenBinding, ServerRequestInterface $request): void
    {
        Assertion::true(TokenBinding::TOKEN_BINDING_STATUS_PRESENT !== $tokenBinding->getStatus(), 'Token binding not supported.');
    }
}
