<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Authentication;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractLoginFormAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnToken;
use function assert;

abstract class WebauthnAuthenticator extends AbstractLoginFormAuthenticator
{
    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        assert($passport instanceof WebauthnPassport, 'Invalid passport');
        $webauthnBadge = $passport->getBadge(WebauthnBadge::class);
        assert($webauthnBadge instanceof WebauthnBadge, 'Invalid badge');
        if ($webauthnBadge->getAuthenticatorResponse() instanceof AuthenticatorAssertionResponse) {
            $authData = $webauthnBadge->getAuthenticatorResponse()
                ->authenticatorData;
        } else {
            $authData = $webauthnBadge->getAuthenticatorResponse()
                ->attestationObject
                ->authData;
        }

        $token = new WebauthnToken(
            $webauthnBadge->getPublicKeyCredentialUserEntity(),
            $webauthnBadge->getPublicKeyCredentialOptions(),
            $webauthnBadge->getPublicKeyCredentialSource()
                ->getPublicKeyCredentialDescriptor(),
            $authData->isUserPresent(),
            $authData->isUserVerified(),
            $authData->getReservedForFutureUse1(),
            $authData->getReservedForFutureUse2(),
            $authData->signCount,
            $authData->extensions,
            $firewallName,
            $webauthnBadge->getUser()
                ->getRoles(),
            $authData->isBackupEligible(),
            $authData->isBackedUp(),
        );
        $token->setUser($webauthnBadge->getUser());

        return $token;
    }
}
