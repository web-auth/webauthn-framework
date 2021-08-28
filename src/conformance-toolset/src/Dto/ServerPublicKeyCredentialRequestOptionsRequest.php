<?php

declare(strict_types=1);

namespace Webauthn\ConformanceToolset\Dto;

use Symfony\Component\Validator\Constraints\Choice;
use Symfony\Component\Validator\Constraints\NotBlank;
use Symfony\Component\Validator\Constraints\Type;
use Webauthn\PublicKeyCredentialRequestOptions;

final class ServerPublicKeyCredentialRequestOptionsRequest
{
    #[Type(type: 'string')]
    #[NotBlank(allowNull: true)]
    public ?string $username = null;

    #[NotBlank(allowNull: true)]
    #[Choice(choices: [PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED, PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED, PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_DISCOURAGED])]
    public ?string $userVerification = null;

    public ?array $extensions = null;
}
