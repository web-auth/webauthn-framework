<?php

declare(strict_types=1);

namespace Webauthn\TokenBinding;

use InvalidArgumentException;
use Psr\Http\Message\ServerRequestInterface;

final class TokenBindingNotSupportedHandler implements TokenBindingHandler
{
    public static function create(): self
    {
        return new self();
    }

    public function check(TokenBinding $tokenBinding, ServerRequestInterface $request): void
    {
        $tokenBinding->getStatus() !== TokenBinding::TOKEN_BINDING_STATUS_PRESENT || throw new InvalidArgumentException(
            'Token binding not supported.'
        );
    }
}
