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

namespace Webauthn\Bundle\DataCollector;

use function Safe\json_encode;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;
use Symfony\Component\VarDumper\Cloner\Data;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Throwable;
use Webauthn\Bundle\Event\AuthenticatorAssertionResponseValidationFailedEvent;
use Webauthn\Bundle\Event\AuthenticatorAssertionResponseValidationSucceededEvent;
use Webauthn\Bundle\Event\AuthenticatorAttestationResponseValidationFailedEvent;
use Webauthn\Bundle\Event\AuthenticatorAttestationResponseValidationSucceededEvent;
use Webauthn\Bundle\Event\PublicKeyCredentialCreationOptionsCreatedEvent;
use Webauthn\Bundle\Event\PublicKeyCredentialRequestOptionsCreatedEvent;

class WebauthnCollector extends DataCollector implements EventSubscriberInterface
{
    private array $publicKeyCredentialCreationOptions = [];

    private array $authenticatorAttestationResponseValidationSucceeded = [];

    private array $authenticatorAttestationResponseValidationFailed = [];

    private array $publicKeyCredentialRequestOptions = [];

    private array $authenticatorAssertionResponseValidationSucceeded = [];

    private array $authenticatorAssertionResponseValidationFailed = [];

    public function collect(Request $request, Response $response, ?Throwable $exception = null): void
    {
        $this->data = [
            'publicKeyCredentialCreationOptions' => $this->publicKeyCredentialCreationOptions,
            'authenticatorAttestationResponseValidationSucceeded' => $this->authenticatorAttestationResponseValidationSucceeded,
            'authenticatorAttestationResponseValidationFailed' => $this->authenticatorAttestationResponseValidationFailed,
            'publicKeyCredentialRequestOptions' => $this->publicKeyCredentialRequestOptions,
            'authenticatorAssertionResponseValidationSucceeded' => $this->authenticatorAssertionResponseValidationSucceeded,
            'authenticatorAssertionResponseValidationFailed' => $this->authenticatorAssertionResponseValidationFailed,
        ];
    }

    /**
     * @return array|Data
     */
    public function getData()
    {
        return $this->data;
    }

    public function getName()
    {
        return 'webauthn_collector';
    }

    public function reset(): void
    {
        $this->data = [];
    }

    public static function getSubscribedEvents(): array
    {
        return [
            PublicKeyCredentialCreationOptionsCreatedEvent::class => ['addPublicKeyCredentialCreationOptions'],
            PublicKeyCredentialRequestOptionsCreatedEvent::class => ['addPublicKeyCredentialRequestOptions'],
            AuthenticatorAttestationResponseValidationSucceededEvent::class => ['addAuthenticatorAttestationResponseValidationSucceeded'],
            AuthenticatorAttestationResponseValidationFailedEvent::class => ['addAuthenticatorAttestationResponseValidationFailed'],
            AuthenticatorAssertionResponseValidationSucceededEvent::class => ['addAuthenticatorAssertionResponseValidationSucceeded'],
            AuthenticatorAssertionResponseValidationFailedEvent::class => ['addAuthenticatorAssertionResponseValidationFailed'],
        ];
    }

    public function addPublicKeyCredentialCreationOptions(PublicKeyCredentialCreationOptionsCreatedEvent $event): self
    {
        $cloner = new VarCloner();
        $this->publicKeyCredentialCreationOptions[] = [
            'options' => $cloner->cloneVar($event->getPublicKeyCredentialCreationOptions()),
            'json' => json_encode($event->getPublicKeyCredentialCreationOptions(), JSON_PRETTY_PRINT),
        ];

        return $this;
    }

    public function addAuthenticatorAttestationResponseValidationSucceeded(AuthenticatorAttestationResponseValidationSucceededEvent $event): self
    {
        $cloner = new VarCloner();
        $this->authenticatorAttestationResponseValidationSucceeded[] = [
            'attestation_response' => $cloner->cloneVar($event->getAuthenticatorAttestationResponse()),
            'options' => $cloner->cloneVar($event->getPublicKeyCredentialCreationOptions()),
            'options_json' => json_encode($event->getPublicKeyCredentialCreationOptions(), JSON_PRETTY_PRINT),
            'credential_source' => $cloner->cloneVar($event->getPublicKeyCredentialSource()),
        ];

        return $this;
    }

    public function addAuthenticatorAttestationResponseValidationFailed(AuthenticatorAttestationResponseValidationFailedEvent $event): self
    {
        $cloner = new VarCloner();
        $this->authenticatorAttestationResponseValidationFailed[] = [
            'attestation_response' => $cloner->cloneVar($event->getAuthenticatorAttestationResponse()),
            'options' => $cloner->cloneVar($event->getPublicKeyCredentialCreationOptions()),
            'options_json' => json_encode($event->getPublicKeyCredentialCreationOptions(), JSON_PRETTY_PRINT),
            'exception' => $cloner->cloneVar($event->getThrowable()),
        ];

        return $this;
    }

    public function addPublicKeyCredentialRequestOptions(PublicKeyCredentialRequestOptionsCreatedEvent $event): self
    {
        $cloner = new VarCloner();
        $this->publicKeyCredentialRequestOptions[] = [
            'options' => $cloner->cloneVar($event->getPublicKeyCredentialRequestOptions()),
            'json' => json_encode($event->getPublicKeyCredentialRequestOptions(), JSON_PRETTY_PRINT),
        ];

        return $this;
    }

    public function addAuthenticatorAssertionResponseValidationSucceeded(AuthenticatorAssertionResponseValidationSucceededEvent $event): self
    {
        $cloner = new VarCloner();
        $this->authenticatorAssertionResponseValidationSucceeded[] = [
            'user_handle' => $cloner->cloneVar($event->getUserHandle()),
            'credential_id' => $cloner->cloneVar($event->getCredentialId()),
            'assertion_response' => $cloner->cloneVar($event->getAuthenticatorAssertionResponse()),
            'options' => $cloner->cloneVar($event->getPublicKeyCredentialRequestOptions()),
            'options_json' => json_encode($event->getPublicKeyCredentialRequestOptions(), JSON_PRETTY_PRINT),
            'credential_source' => $cloner->cloneVar($event->getPublicKeyCredentialSource()),
        ];

        return $this;
    }

    public function addAuthenticatorAssertionResponseValidationFailed(AuthenticatorAssertionResponseValidationFailedEvent $event): self
    {
        $cloner = new VarCloner();
        $this->authenticatorAssertionResponseValidationFailed[] = [
            'user_handle' => $cloner->cloneVar($event->getUserHandle()),
            'credential_id' => $cloner->cloneVar($event->getCredentialId()),
            'assertion_response' => $cloner->cloneVar($event->getAuthenticatorAssertionResponse()),
            'options' => $cloner->cloneVar($event->getPublicKeyCredentialRequestOptions()),
            'options_json' => json_encode($event->getPublicKeyCredentialRequestOptions(), JSON_PRETTY_PRINT),
            'exception' => $cloner->cloneVar($event->getThrowable()),
        ];

        return $this;
    }
}
