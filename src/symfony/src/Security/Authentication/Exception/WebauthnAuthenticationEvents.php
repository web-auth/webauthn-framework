<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Authentication\Exception;

interface WebauthnAuthenticationEvents
{
    public const FAILURE = 'failure';

    public const SUCCESS = 'success';
}
