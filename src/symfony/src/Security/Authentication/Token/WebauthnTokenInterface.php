<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * @deprecated since 4.7.0, use {@see WebauthnTokenInterface} instead
 */
interface WebauthnTokenInterface extends TokenInterface
{
    public function getCredentials(): PublicKeyCredentialDescriptor;

    public function getPublicKeyCredentialUserEntity(): PublicKeyCredentialUserEntity;

    public function getPublicKeyCredentialDescriptor(): PublicKeyCredentialDescriptor;

    public function getPublicKeyCredentialOptions(): PublicKeyCredentialOptions;

    public function isUserPresent(): bool;

    public function isUserVerified(): bool;

    public function getReservedForFutureUse1(): int;

    public function getReservedForFutureUse2(): int;

    public function getSignCount(): int;

    public function getExtensions(): ?AuthenticationExtensionsClientOutputs;

    public function getFirewallName(): string;
}
