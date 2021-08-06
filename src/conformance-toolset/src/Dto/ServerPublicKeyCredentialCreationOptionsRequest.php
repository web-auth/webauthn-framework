<?php

declare(strict_types=1);

namespace Webauthn\ConformanceToolset\Dto;

use Symfony\Component\Validator\Constraints as Assert;
use Webauthn\PublicKeyCredentialCreationOptions;

final class ServerPublicKeyCredentialCreationOptionsRequest
{
    /**
     * @Assert\Type("string")
     * @Assert\NotBlank
     */
    public string $username = '';

    /**
     * @Assert\Type("string")
     * @Assert\NotBlank
     */
    public string $displayName = '';

    public ?array $authenticatorSelection = null;

    /**
     * @Assert\NotBlank(allowNull=true)
     * @Assert\Choice({PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE, PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT, PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT})
     */
    public ?string $attestation = null;

    public ?array $extensions = null;
}
