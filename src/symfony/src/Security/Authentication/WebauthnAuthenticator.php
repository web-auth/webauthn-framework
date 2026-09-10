<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Authentication;

use function assert;
use function ord;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractLoginFormAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorData;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnToken;

abstract class WebauthnAuthenticator extends AbstractLoginFormAuthenticator
{
    /**
     * The RFU flags are read from the raw flags byte instead of the deprecated AuthenticatorData accessors, so that the
     * deprecated WebauthnToken arguments keep receiving the very same values without emitting a deprecation notice.
     */
    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        assert($passport instanceof WebauthnPassport, 'Invalid passport');
        $webauthnBadge = $passport->getBadge(WebauthnBadge::class);
        assert($webauthnBadge instanceof WebauthnBadge, 'Invalid badge');
        $response = $webauthnBadge->getAuthenticatorResponse();
        if ($response instanceof AuthenticatorAssertionResponse) {
            $authData = $response->authenticatorData;
        } else {
            assert($response instanceof AuthenticatorAttestationResponse);
            $authData = $response->attestationObject->authData;
        }
        /** @var AuthenticatorData $authData */
        $flags = ord($authData->flags);
        $token = new WebauthnToken(
            $webauthnBadge->getPublicKeyCredentialUserEntity(),
            $webauthnBadge->getPublicKeyCredentialOptions(),
            $webauthnBadge->getPublicKeyCredentialSource()
                ->getPublicKeyCredentialDescriptor(),
            $authData->isUserPresent(),
            $authData->isUserVerified(),
            $flags & AuthenticatorData::FLAG_RFU1,
            $flags & AuthenticatorData::FLAG_RFU2,
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
