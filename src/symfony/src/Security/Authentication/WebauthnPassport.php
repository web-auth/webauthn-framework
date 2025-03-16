<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Authentication;

use LogicException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\BadgeInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\PreAuthenticatedUserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

final class WebauthnPassport extends Passport
{
    /**
     * @param BadgeInterface[] $badges
     */
    public function __construct(WebauthnBadge $webauthnBadge, array $badges = [])
    {
        $this->addBadge($webauthnBadge);
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
