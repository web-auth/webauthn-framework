<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Dto;

use Symfony\Component\Validator\Constraints\Choice;
use Symfony\Component\Validator\Constraints\Type;
use Webauthn\PublicKeyCredentialCreationOptions;

final class AdditionalPublicKeyCredentialCreationOptionsRequest
{
    /**
     * @var array<mixed>|null
     */
    public ?array $authenticatorSelection = null;

    #[Type(type: 'string')]
    #[Choice(choices: [
        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT,
    ])]
    public string $attestation = PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE;

    /**
     * @var array<string, mixed>|null
     */
    public ?array $extensions = null;
}
