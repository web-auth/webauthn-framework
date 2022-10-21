<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\HttpUtils;
use Webauthn\Bundle\DependencyInjection\Factory\Security\WebauthnFactory;

final class WebauthnFirewallConfig
{
    /**
     * @param array<string,mixed> $options
     */
    public function __construct(
        private readonly array $options,
        private readonly string $firewallName,
        private readonly HttpUtils $httpUtils,
    ) {
    }

    public function getFirewallName(): string
    {
        return $this->firewallName;
    }

    public function getUserProvider(): ?string
    {
        return $this->options['user_provider'] ?? null;
    }

    public function getOptionsStorage(): string
    {
        return $this->options['options_storage'] ?? WebauthnFactory::DEFAULT_SESSION_STORAGE_SERVICE;
    }

    public function getSuccessHandler(): string
    {
        return $this->options['success_handler'] ?? WebauthnFactory::DEFAULT_SUCCESS_HANDLER_SERVICE;
    }

    public function getFailureHandler(): string
    {
        return $this->options['success_handler'] ?? WebauthnFactory::DEFAULT_FAILURE_HANDLER_SERVICE;
    }

    public function isAuthenticationEnabled(): bool
    {
        return $this->options['authentication']['enabled'] ?? true;
    }

    public function getAuthenticationProfile(): string
    {
        return $this->options['authentication']['profile'] ?? 'default';
    }

    public function getAuthenticationOptionsHandler(): string
    {
        return $this->options['authentication']['options_handler'] ?? WebauthnFactory::DEFAULT_REQUEST_OPTIONS_HANDLER_SERVICE;
    }

    public function getAuthenticationHost(): ?string
    {
        return $this->options['authentication']['routes']['host'] ?? null;
    }

    public function getAuthenticationOptionsMethod(): string
    {
        return $this->options['authentication']['routes']['options_method'] ?? WebauthnFactory::DEFAULT_LOGIN_OPTIONS_METHOD;
    }

    public function getAuthenticationOptionsPath(): string
    {
        return $this->options['authentication']['routes']['options_path'] ?? WebauthnFactory::DEFAULT_LOGIN_OPTIONS_PATH;
    }

    public function getAuthenticationResultMethod(): string
    {
        return $this->options['authentication']['routes']['result_method'] ?? WebauthnFactory::DEFAULT_LOGIN_RESULT_METHOD;
    }

    public function getAuthenticationResultPath(): string
    {
        return $this->options['authentication']['routes']['result_path'] ?? WebauthnFactory::DEFAULT_LOGIN_RESULT_PATH;
    }

    public function isRegistrationEnabled(): bool
    {
        return $this->options['registration']['enabled'] ?? true;
    }

    public function getRegistrationProfile(): string
    {
        return $this->options['registration']['profile'] ?? 'default';
    }

    public function getRegistrationOptionsHandler(): string
    {
        return $this->options['registration']['options_handler'] ?? WebauthnFactory::DEFAULT_REQUEST_OPTIONS_HANDLER_SERVICE;
    }

    public function getRegistrationHost(): ?string
    {
        return $this->options['registration']['routes']['host'] ?? null;
    }

    public function getRegistrationOptionsMethod(): string
    {
        return $this->options['registration']['routes']['options_method'] ?? WebauthnFactory::DEFAULT_REGISTER_OPTIONS_METHOD;
    }

    public function getRegistrationOptionsPath(): string
    {
        return $this->options['registration']['routes']['options_path'] ?? WebauthnFactory::DEFAULT_REGISTER_OPTIONS_PATH;
    }

    public function getRegistrationResultMethod(): string
    {
        return $this->options['registration']['routes']['result_method'] ?? WebauthnFactory::DEFAULT_REGISTER_RESULT_METHOD;
    }

    public function getRegistrationResultPath(): string
    {
        return $this->options['registration']['routes']['result_path'] ?? WebauthnFactory::DEFAULT_REGISTER_RESULT_PATH;
    }

    /**
     * @return string[]
     */
    public function getSecuredRpIds(): array
    {
        return $this->options['secured_rp_ids'] ?? [];
    }

    public function isAuthenticationOptionsPathRequest(Request $request): bool
    {
        return $this->httpUtils->checkRequestPath($request, $this->getAuthenticationOptionsPath());
    }

    public function isAuthenticationResultPathRequest(Request $request): bool
    {
        return $this->httpUtils->checkRequestPath($request, $this->getAuthenticationResultPath());
    }

    public function isRegistrationOptionsPathRequest(Request $request): bool
    {
        return $this->httpUtils->checkRequestPath($request, $this->getRegistrationOptionsPath());
    }

    public function isRegistrationResultPathRequest(Request $request): bool
    {
        return $this->httpUtils->checkRequestPath($request, $this->getRegistrationResultPath());
    }
}
