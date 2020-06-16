<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Security\Voter;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnToken;

final class IsUserPresentVoter implements VoterInterface
{
    public const IS_USER_PRESENT = 'IS_USER_PRESENT';

    /**
     * {@inheritdoc}
     *
     * @param mixed $subject
     */
    public function vote(TokenInterface $token, $subject, array $attributes): int
    {
        $result = VoterInterface::ACCESS_ABSTAIN;
        if (!$token instanceof WebauthnToken) {
            return $result;
        }

        foreach ($attributes as $attribute) {
            if (self::IS_USER_PRESENT !== $attribute) {
                continue;
            }

            return $token->isUserPresent() ? VoterInterface::ACCESS_GRANTED : VoterInterface::ACCESS_DENIED;
        }

        return $result;
    }
}
