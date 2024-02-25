<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Authentication\Exception;

interface WebauthnAuthenticationEvents
{
    public const string FAILURE = 'failure';

    public const string SUCCESS = 'success';
}
