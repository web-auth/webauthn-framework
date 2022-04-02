<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DataCollector;

use const JSON_PRETTY_PRINT;
use const JSON_THROW_ON_ERROR;
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
    /**
     * @var array<mixed>
     */
    private array $publicKeyCredentialCreationOptions = [];

    /**
     * @var array<mixed>
     */
    private array $authenticatorAttestationResponseValidationSucceeded = [];

    /**
     * @var array<mixed>
     */
    private array $authenticatorAttestationResponseValidationFailed = [];

    /**
     * @var array<mixed>
     */
    private array $publicKeyCredentialRequestOptions = [];

    /**
     * @var array<mixed>
     */
    private array $authenticatorAssertionResponseValidationSucceeded = [];

    /**
     * @var array<mixed>
     */
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
     * @return array<mixed>|Data
     */
    public function getData(): array|Data
    {
        return $this->data;
    }

    public function getName(): string
    {
        return 'webauthn_collector';
    }

    public function reset(): void
    {
        $this->data = [];
    }

    /**
     * {@inheritDoc}
     *
     * @return array<string, string|array{0: string, 1: int}|list<array{0: string, 1?: int}>>
     */
    public static function getSubscribedEvents(): array
    {
        return [
            PublicKeyCredentialCreationOptionsCreatedEvent::class => ['addPublicKeyCredentialCreationOptions'],
            PublicKeyCredentialRequestOptionsCreatedEvent::class => ['addPublicKeyCredentialRequestOptions'],
            AuthenticatorAttestationResponseValidationSucceededEvent::class => [
                'addAuthenticatorAttestationResponseValidationSucceeded',
            ],
            AuthenticatorAttestationResponseValidationFailedEvent::class => [
                'addAuthenticatorAttestationResponseValidationFailed',
            ],
            AuthenticatorAssertionResponseValidationSucceededEvent::class => [
                'addAuthenticatorAssertionResponseValidationSucceeded',
            ],
            AuthenticatorAssertionResponseValidationFailedEvent::class => [
                'addAuthenticatorAssertionResponseValidationFailed',
            ],
        ];
    }

    public function addPublicKeyCredentialCreationOptions(PublicKeyCredentialCreationOptionsCreatedEvent $event): void
    {
        $cloner = new VarCloner();
        $this->publicKeyCredentialCreationOptions[] = [
            'options' => $cloner->cloneVar($event->getPublicKeyCredentialCreationOptions()),
            'json' => json_encode(
                $event->getPublicKeyCredentialCreationOptions(),
                JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT
            ),
        ];
    }

    public function addAuthenticatorAttestationResponseValidationSucceeded(
        AuthenticatorAttestationResponseValidationSucceededEvent $event
    ): void {
        $cloner = new VarCloner();
        $this->authenticatorAttestationResponseValidationSucceeded[] = [
            'attestation_response' => $cloner->cloneVar($event->getAuthenticatorAttestationResponse()),
            'options' => $cloner->cloneVar($event->getPublicKeyCredentialCreationOptions()),
            'options_json' => json_encode(
                $event->getPublicKeyCredentialCreationOptions(),
                JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT
            ),
            'credential_source' => $cloner->cloneVar($event->getPublicKeyCredentialSource()),
        ];
    }

    public function addAuthenticatorAttestationResponseValidationFailed(
        AuthenticatorAttestationResponseValidationFailedEvent $event
    ): void {
        $cloner = new VarCloner();
        $this->authenticatorAttestationResponseValidationFailed[] = [
            'attestation_response' => $cloner->cloneVar($event->getAuthenticatorAttestationResponse()),
            'options' => $cloner->cloneVar($event->getPublicKeyCredentialCreationOptions()),
            'options_json' => json_encode(
                $event->getPublicKeyCredentialCreationOptions(),
                JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT
            ),
            'exception' => $cloner->cloneVar($event->getThrowable()),
        ];
    }

    public function addPublicKeyCredentialRequestOptions(PublicKeyCredentialRequestOptionsCreatedEvent $event): void
    {
        $cloner = new VarCloner();
        $this->publicKeyCredentialRequestOptions[] = [
            'options' => $cloner->cloneVar($event->getPublicKeyCredentialRequestOptions()),
            'json' => json_encode(
                $event->getPublicKeyCredentialRequestOptions(),
                JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT
            ),
        ];
    }

    public function addAuthenticatorAssertionResponseValidationSucceeded(
        AuthenticatorAssertionResponseValidationSucceededEvent $event
    ): void {
        $cloner = new VarCloner();
        $this->authenticatorAssertionResponseValidationSucceeded[] = [
            'user_handle' => $cloner->cloneVar($event->getUserHandle()),
            'credential_id' => $cloner->cloneVar($event->getCredentialId()),
            'assertion_response' => $cloner->cloneVar($event->getAuthenticatorAssertionResponse()),
            'options' => $cloner->cloneVar($event->getPublicKeyCredentialRequestOptions()),
            'options_json' => json_encode(
                $event->getPublicKeyCredentialRequestOptions(),
                JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT
            ),
            'credential_source' => $cloner->cloneVar($event->getPublicKeyCredentialSource()),
        ];
    }

    public function addAuthenticatorAssertionResponseValidationFailed(
        AuthenticatorAssertionResponseValidationFailedEvent $event
    ): void {
        $cloner = new VarCloner();
        $this->authenticatorAssertionResponseValidationFailed[] = [
            'user_handle' => $cloner->cloneVar($event->getUserHandle()),
            'credential_id' => $cloner->cloneVar($event->getCredentialId()),
            'assertion_response' => $cloner->cloneVar($event->getAuthenticatorAssertionResponse()),
            'options' => $cloner->cloneVar($event->getPublicKeyCredentialRequestOptions()),
            'options_json' => json_encode(
                $event->getPublicKeyCredentialRequestOptions(),
                JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT
            ),
            'exception' => $cloner->cloneVar($event->getThrowable()),
        ];
    }
}
