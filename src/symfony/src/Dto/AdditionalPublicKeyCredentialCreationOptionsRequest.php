<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Dto;

use Symfony\Component\Validator\Constraints\Choice;
use Symfony\Component\Validator\Constraints\NotBlank;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;

final class AdditionalPublicKeyCredentialCreationOptionsRequest
{
    /**
     * @var array<mixed>|null
     *
     * @deprecated Use $userVerification, $residentKey and $authenticatorAttachment
     */
    public ?array $authenticatorSelection = null;

    #[NotBlank(allowNull: true)]
    #[Choice(choices: [
        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT,
    ])]
    public ?string $attestation = null;

    #[NotBlank(allowNull: true)]
    #[Choice(choices: [
        AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
        AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
        AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
    ])]
    public ?string $userVerification = null;

    #[NotBlank(allowNull: true)]
    #[Choice(choices: [
        AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_NO_PREFERENCE,
        AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
        AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED,
        AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_DISCOURAGED,
    ])]
    public ?string $residentKey = null;

    #[NotBlank(allowNull: true)]
    #[Choice(choices: [
        AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE,
        AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
        AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
    ])]
    public ?string $authenticatorAttachment = null;

    /**
     * @var array<string, mixed>|null
     */
    public ?array $extensions = null;
}
