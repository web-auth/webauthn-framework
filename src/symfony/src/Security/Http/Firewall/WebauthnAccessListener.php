<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Http\Firewall;

use  Symfony\Component\HttpFoundation\Request;
use  Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Http\Firewall\AbstractListener;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnTokenInterface;
use Webauthn\Bundle\Security\Authorization\WebauthnAccessDecider;
use Webauthn\Bundle\Security\WebauthnFirewallConfig;

final class WebauthnAccessListener extends AbstractListener
{
    public function __construct(
        private WebauthnFirewallConfig $webauthnFirewallConfig,
        private TokenStorageInterface $tokenStorage,
        private WebauthnAccessDecider $webauthnAccessDecider,
    ) {
    }

    public function supports(Request $request): ?bool
    {
        // When the path is explicitly configured for anonymous access, no need to check access (important for lazy
        // firewalls, to prevent the response cache control to be flagged "private")
        return ! $this->webauthnAccessDecider->isPubliclyAccessible($request);
    }

    public function authenticate(RequestEvent $event): void
    {
        // When the firewall is lazy, the token is not initialized in the "supports" stage, so this check does only work
        // within the "authenticate" stage.
        $token = $this->tokenStorage->getToken();
        if (! $token instanceof WebauthnTokenInterface) {
            // No need to check for firewall name here, the listener is bound to the firewall context
            return;
        }

        $request = $event->getRequest();
        if ($this->webauthnFirewallConfig->isCheckPathRequest($request)) {
            return;
        }

        if ($this->webauthnFirewallConfig->isAuthFormRequest($request)) {
            return;
        }

        if (! $this->webauthnAccessDecider->isAccessible($request, $token)) {
            $exception = new AccessDeniedException('User is in a two-factor authentication process.');
            $exception->setSubject($request);

            throw $exception;
        }
    }

    public static function getPriority(): int
    {
        // When the class is injected via FirewallListenerFactoryInterface
        // Inject before Symfony's AccessListener (-255) and after the LogoutListener (-127)
        return -191;
    }
}
