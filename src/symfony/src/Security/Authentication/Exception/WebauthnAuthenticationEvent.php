<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Authentication\Exception;

use Symfony\Component\Security\Core\Exception\BadCredentialsException;

final class WebauthnAuthenticationEvent extends BadCredentialsException
{
    private const string MESSAGE_KEY = 'invalid';

    public function getMessageKey(): string
    {
        return self::MESSAGE_KEY;
    }
}
