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

namespace Webauthn\Bundle\Security\Firewall;

use LogicException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\HttpUtils;

class WebauthnListener
{
    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    /**
     * @var array<string, mixed>
     */
    private $options;

    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @var HttpUtils
     */
    private $httpUtils;

    /**
     * @var RequestListener
     */
    private $requestListener;

    /**
     * @var CreationListener
     */
    private $creationListener;

    /**
     * @param array<string, mixed> $options
     */
    public function __construct(HttpUtils $httpUtils, ?LoggerInterface $logger, RequestListener $requestListener, CreationListener $creationListener, array $options)
    {
        $this->httpUtils = $httpUtils;
        $this->options = $options;
        $this->logger = $logger ?? new NullLogger();
        $this->requestListener = $requestListener;
        $this->creationListener = $creationListener;
    }

    public function __invoke(RequestEvent $event): void
    {
        $this->logger->debug('Webauthn Listener called');
        $request = $event->getRequest();
        if (!$request->isMethod(Request::METHOD_POST)) {
            $this->logger->debug('The request method is not a POST. Ignored');

            return;
        }
        if (false === mb_strpos($request->getRequestFormat(), 'json') && false === mb_strpos($request->getContentType(), 'json')) {
            $this->logger->debug('The request format and the content type are not JSON. Ignored');

            return;
        }

        if (!$request->hasSession()) {
            $this->logger->debug('Error: no session available.');
            throw new LogicException('This authentication method requires a session.');
        }

        switch (true) {
            case true === $this->options['authentication']['enabled'] && $this->httpUtils->checkRequestPath($request, $this->options['authentication']['routes']['result_path']):
                $this->logger->debug('The path corresponds to the request result path');
                $this->requestListener->processWithRequestResult($event);

                return;
            case true === $this->options['authentication']['enabled'] && $this->httpUtils->checkRequestPath($request, $this->options['authentication']['routes']['options_path']):
                $this->logger->debug('The path corresponds to the request options path');
                $this->requestListener->processWithRequestOptions($event);

                return;
            case true === $this->options['registration']['enabled'] && $this->httpUtils->checkRequestPath($request, $this->options['registration']['routes']['result_path']):
                $this->logger->debug('The path corresponds to the creation result path');
                $this->creationListener->processWithCreationResult($event);

                return;
            case true === $this->options['registration']['enabled'] && $this->httpUtils->checkRequestPath($request, $this->options['registration']['routes']['options_path']):
                $this->logger->debug('The path corresponds to the creation options path');
                $this->creationListener->processWithCreationOptions($event);

                return;
            default:
                $this->logger->debug('The path does not corresponds to any configured path. Ignored', ['query' => $request->getQueryString()]);

                return;
        }
    }
}
