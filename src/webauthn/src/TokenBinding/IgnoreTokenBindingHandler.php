<?php

declare(strict_types=1);

namespace Webauthn\TokenBinding;

use Psr\Http\Message\ServerRequestInterface;

final class IgnoreTokenBindingHandler implements TokenBindingHandler
{
    public static function create(): self
    {
        return new self();
    }

    public function check(TokenBinding $tokenBinding, ServerRequestInterface $request): void
    {
        //Does nothing
    }
}
