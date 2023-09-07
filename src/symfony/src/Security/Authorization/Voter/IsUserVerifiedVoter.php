<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Authorization\Voter;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnToken;

final class IsUserVerifiedVoter implements VoterInterface
{
    public const IS_USER_VERIFIED = 'IS_USER_VERIFIED';

    public function vote(TokenInterface $token, mixed $subject, array $attributes): int
    {
        $result = VoterInterface::ACCESS_ABSTAIN;
        if (! $token instanceof WebauthnToken) {
            return $result;
        }

        foreach ($attributes as $attribute) {
            if ($attribute !== self::IS_USER_VERIFIED) {
                continue;
            }

            return $token->isUserVerified() ? VoterInterface::ACCESS_GRANTED : VoterInterface::ACCESS_DENIED;
        }

        return $result;
    }
}
