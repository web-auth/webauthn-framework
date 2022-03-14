<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Authentication\Exception;

use Symfony\Component\Security\Core\Exception\BadCredentialsException;

final class WebauthnAuthenticationEvent extends BadCredentialsException
{
    public const MESSAGE = 'Invalid Webauthn credentials.';

    private const MESSAGE_KEY = 'invalid';

    public function getMessageKey(): string
    {
        return self::MESSAGE_KEY;
    }
}
