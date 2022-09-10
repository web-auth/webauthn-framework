<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Dto;

use Symfony\Component\Validator\Constraints\NotBlank;

final class ServerPublicKeyCredentialCreationOptionsRequest extends PublicKeyCredentialCreationOptionsRequest
{
    #[NotBlank]
    public string $username = '';

    #[NotBlank]
    public string $displayName = '';
}
