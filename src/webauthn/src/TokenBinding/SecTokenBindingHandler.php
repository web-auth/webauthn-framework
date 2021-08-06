<?php

declare(strict_types=1);

namespace Webauthn\TokenBinding;

use Assert\Assertion;
use JetBrains\PhpStorm\Pure;
use Psr\Http\Message\ServerRequestInterface;

final class SecTokenBindingHandler implements TokenBindingHandler
{
    #[Pure]
    public static function create(): self
    {
        return new self();
    }

    public function check(TokenBinding $tokenBinding, ServerRequestInterface $request): void
    {
        if (TokenBinding::TOKEN_BINDING_STATUS_PRESENT !== $tokenBinding->getStatus()) {
            return;
        }

        Assertion::true($request->hasHeader('Sec-Token-Binding'), 'The header parameter "Sec-Token-Binding" is missing.');
        $tokenBindingIds = $request->getHeader('Sec-Token-Binding');
        Assertion::count($tokenBindingIds, 1, 'The header parameter "Sec-Token-Binding" is invalid.');
        $tokenBindingId = reset($tokenBindingIds);
        Assertion::eq($tokenBindingId, $tokenBinding->getId(), 'The header parameter "Sec-Token-Binding" is invalid.');
    }
}
