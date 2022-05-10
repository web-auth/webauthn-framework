<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Dto;

use Symfony\Component\Validator\Constraints\Choice;
use Symfony\Component\Validator\Constraints\NotBlank;
use Symfony\Component\Validator\Constraints\Type;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;

final class ServerPublicKeyCredentialCreationOptionsRequest
{
    #[Type(type: 'string')]
    #[NotBlank]
    public string $username = '';

    #[Type(type: 'string')]
    #[NotBlank]
    public string $displayName = '';

    /**
     * @var array<mixed>|null
     *
     * @deprecated Use $userVerification, $residentKey and $authenticatorAttachment
     */
    public ?array $authenticatorSelection = null;

    #[Type(type: 'string')]
    #[Choice(choices: [
        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT,
    ])]
    public string $attestation = PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE;

    #[Type(type: 'string')]
    #[NotBlank(allowNull: true)]
    #[Choice(choices: [
        AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
        AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
        AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
    ])]
    public ?string $userVerification = AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED;

    #[Type(type: 'string')]
    #[NotBlank(allowNull: true)]
    #[Choice(choices: [
        AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_NO_PREFERENCE,
        AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
        AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED,
        AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_DISCOURAGED,
    ])]
    public ?string $residentKey = AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED;

    #[Type(type: 'string')]
    #[NotBlank(allowNull: true)]
    #[Choice(choices: [
        AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE,
        AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
        AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
    ])]
    public ?string $authenticatorAttachment = AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE;

    /**
     * @var array<string, mixed>|null
     */
    public ?array $extensions = null;
}
