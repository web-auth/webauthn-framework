<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Authentication\Token;

use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialUserEntity;

interface WebauthnTokenFactoryInterface
{
    public function create(
        PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity,
        PublicKeyCredentialOptions $publicKeyCredentialOptions,
        PublicKeyCredentialDescriptor $publicKeyCredentialDescriptor,
        bool $isUserPresent,
        bool $isUserVerified,
        int $reservedForFutureUse1,
        int $reservedForFutureUse2,
        int $signCount,
        ?AuthenticationExtensionsClientOutputs $extensions,
        string $providerKey,
        array $roles = []
    ): WebauthnTokenInterface;
}
