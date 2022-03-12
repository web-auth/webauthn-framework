<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Event;

use Psr\Http\Message\ServerRequestInterface;
use Symfony\Contracts\EventDispatcher\Event;
use Throwable;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\PublicKeyCredentialRequestOptions;

class AuthenticatorAssertionResponseValidationFailedEvent extends Event
{
    
    public function __construct(private string $credentialId, private AuthenticatorAssertionResponse $authenticatorAssertionResponse, private PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions, private ServerRequestInterface $request, private ?string $userHandle, private Throwable $throwable)
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

    
    public function getThrowable(): Throwable
    {
        return $this->throwable;
    }
}
