<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\DataCollector;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;
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
    /**
     * @var array
     */
    private $publicKeyCredentialCreationOptions = [];

    /**
     * @var array
     */
    private $authenticatorAttestationResponseValidationSucceeded = [];

    /**
     * @var array
     */
    private $authenticatorAttestationResponseValidationFailed = [];

    /**
     * @var array
     */
    private $publicKeyCredentialRequestOptions = [];

    /**
     * @var array
     */
    private $authenticatorAssertionResponseValidationSucceeded = [];

    /**
     * @var array
     */
    private $authenticatorAssertionResponseValidationFailed = [];

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

    public function addPublicKeyCredentialCreationOptions(PublicKeyCredentialCreationOptionsCreatedEvent $event): void
    {
        $cloner = new VarCloner();
        $this->publicKeyCredentialCreationOptions[] = [
            'options' => $cloner->cloneVar($event->getPublicKeyCredentialCreationOptions()),
            'json' => json_encode($event->getPublicKeyCredentialCreationOptions(), JSON_PRETTY_PRINT),
        ];
    }

    public function addAuthenticatorAttestationResponseValidationSucceeded(AuthenticatorAttestationResponseValidationSucceededEvent $event): void
    {
        $cloner = new VarCloner();
        $this->authenticatorAttestationResponseValidationSucceeded[] = [
            'attestation_response' => $cloner->cloneVar($event->getAuthenticatorAttestationResponse()),
            'options' => $cloner->cloneVar($event->getPublicKeyCredentialCreationOptions()),
            'options_json' => json_encode($event->getPublicKeyCredentialCreationOptions(), JSON_PRETTY_PRINT),
            'credential_source' => $cloner->cloneVar($event->getPublicKeyCredentialSource()),
        ];
    }

    public function addAuthenticatorAttestationResponseValidationFailed(AuthenticatorAttestationResponseValidationFailedEvent $event): void
    {
        $cloner = new VarCloner();
        $this->authenticatorAttestationResponseValidationFailed[] = [
            'attestation_response' => $cloner->cloneVar($event->getAuthenticatorAttestationResponse()),
            'options' => $cloner->cloneVar($event->getPublicKeyCredentialCreationOptions()),
            'options_json' => json_encode($event->getPublicKeyCredentialCreationOptions(), JSON_PRETTY_PRINT),
            'exception' => $cloner->cloneVar($event->getThrowable()),
        ];
    }

    public function addPublicKeyCredentialRequestOptions(PublicKeyCredentialRequestOptionsCreatedEvent $event): void
    {
        $cloner = new VarCloner();
        $this->publicKeyCredentialRequestOptions[] = [
            'options' => $cloner->cloneVar($event->getPublicKeyCredentialRequestOptions()),
            'json' => json_encode($event->getPublicKeyCredentialRequestOptions(), JSON_PRETTY_PRINT),
        ];
    }

    public function addAuthenticatorAssertionResponseValidationSucceeded(AuthenticatorAssertionResponseValidationSucceededEvent $event): void
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
    }

    public function addAuthenticatorAssertionResponseValidationFailed(AuthenticatorAssertionResponseValidationFailedEvent $event): void
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
    }
}
