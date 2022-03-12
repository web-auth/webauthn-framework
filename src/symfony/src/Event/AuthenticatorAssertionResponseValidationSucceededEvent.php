<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Event;

use Psr\Http\Message\ServerRequestInterface;
use Symfony\Contracts\EventDispatcher\Event;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;

class AuthenticatorAssertionResponseValidationSucceededEvent extends Event
{
    
    public function __construct(private string $credentialId, private AuthenticatorAssertionResponse $authenticatorAssertionResponse, private PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions, private ServerRequestInterface $request, private ?string $userHandle, private PublicKeyCredentialSource $publicKeyCredentialSource)
    {
    }

    
    public function getCredentialId(): string
    {
        return $this->credentialId;
    }

    
    public function getAuthenticatorAssertionResponse(): AuthenticatorAssertionResponse
    {
        return $this->authenticatorAssertionResponse;
    }

    
    public function getPublicKeyCredentialRequestOptions(): PublicKeyCredentialRequestOptions
    {
        return $this->publicKeyCredentialRequestOptions;
    }

    
    public function getRequest(): ServerRequestInterface
    {
        return $this->request;
    }

    
    public function getUserHandle(): ?string
    {
        return $this->userHandle;
    }

    
    public function getPublicKeyCredentialSource(): PublicKeyCredentialSource
    {
        return $this->publicKeyCredentialSource;
    }
}
