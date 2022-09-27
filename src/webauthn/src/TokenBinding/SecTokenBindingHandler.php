<?php

declare(strict_types=1);

namespace Webauthn\TokenBinding;

use function count;
use InvalidArgumentException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * @deprecated Since 4.3.0 and will be removed in 5.0.0
 */
final class SecTokenBindingHandler implements TokenBindingHandler
{
    public static function create(): self
    {
        return new self();
    }

    public function check(TokenBinding $tokenBinding, ServerRequestInterface $request): void
    {
        if ($tokenBinding->getStatus() !== TokenBinding::TOKEN_BINDING_STATUS_PRESENT) {
            return;
        }

        $request->hasHeader('Sec-Token-Binding') || throw new InvalidArgumentException(
            'The header parameter "Sec-Token-Binding" is missing.'
        );
        $tokenBindingIds = $request->getHeader('Sec-Token-Binding');
        count($tokenBindingIds) === 1 || throw new InvalidArgumentException(
            'The header parameter "Sec-Token-Binding" is invalid.'
        );
        $tokenBindingId = reset($tokenBindingIds);
        $tokenBindingId === $tokenBinding->getId() || throw new InvalidArgumentException(
            'The header parameter "Sec-Token-Binding" is invalid.'
        );
    }
}
