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

use Exception;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;
use Symfony\Component\VarDumper\Cloner\Data;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Webauthn\Bundle\Event\PublicKeyCredentialCreationOptionsCreatedEvent;

class WebauthnCollector extends DataCollector implements EventSubscriberInterface
{
    /**
     * @var Data[]
     */
    private $publicKeyCredentialCreationOptions = [];

    public function collect(Request $request, Response $response, ?Exception $exception = null): void
    {
        $this->data =[
            'publicKeyCredentialCreationOptions' => $this->publicKeyCredentialCreationOptions,
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
        ];
    }

    public function addPublicKeyCredentialCreationOptions(PublicKeyCredentialCreationOptionsCreatedEvent $event): void
    {
        $cloner = new VarCloner();
        $this->publicKeyCredentialCreationOptions[] = $cloner->cloneVar($event->getPublicKeyCredentialCreationOptions());
    }
}
