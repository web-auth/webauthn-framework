<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Dto;

use Symfony\Component\Validator\Constraints\Choice;
use Symfony\Component\Validator\Constraints\NotBlank;
use Symfony\Component\Validator\Constraints\Type;
use Webauthn\PublicKeyCredentialCreationOptions;

final class ServerPublicKeyCredentialCreationOptionsRequest
{
    #[Type(type: 'string')]
    #[NotBlank]
    public string $username = '';

    #[Type(type: 'string')]
    #[NotBlank]
    public string $displayName = '';

    public ?array $authenticatorSelection = null;

    #[Type(type: 'string')]
    #[Choice(choices: [
        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT,
    ])]
    public string $attestation = PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE;

    public ?array $extensions = null;
}
