<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Authentication;

use LogicException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\BadgeInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\PreAuthenticatedUserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

final class WebauthnPassport extends Passport
{
    /**
     * The WebAuthn badge is also registered as the user badge of the passport. The user provider listener that
     * Symfony attaches to the firewall then installs the provider of that firewall as the user loader of the badge,
     * instead of the chain of every user provider of the application, which returns the first account that matches
     * the username, whatever its provider.
     *
     * @param BadgeInterface[] $badges
     */
    public function __construct(WebauthnBadge $webauthnBadge, array $badges = [])
    {
        $this->addBadge($webauthnBadge);
        $this->addBadge($webauthnBadge, UserBadge::class);
        $this->addBadge(new PreAuthenticatedUserBadge());
        foreach ($badges as $badge) {
            $this->addBadge($badge);
        }
    }

    public function getUser(): UserInterface
    {
        $webauthnBadge = $this->getBadge(WebauthnBadge::class);
        if ($webauthnBadge === null || ! $webauthnBadge instanceof WebauthnBadge) {
            throw new LogicException('No WebauthnBadge found in the passport.');
        }

        return $webauthnBadge->getUser();
    }
}
