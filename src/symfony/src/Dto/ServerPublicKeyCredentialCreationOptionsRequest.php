<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Dto;

use Symfony\Component\Validator\Constraints\NotBlank;

final class ServerPublicKeyCredentialCreationOptionsRequest extends PublicKeyCredentialCreationOptionsRequest
{
    #[NotBlank(allowNull: true)]
    public ?string $username = null;

    #[NotBlank(allowNull: true)]
    public ?string $displayName = null;
}
