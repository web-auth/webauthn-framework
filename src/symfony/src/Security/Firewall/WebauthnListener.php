<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Firewall;

use function is_string;
use LogicException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\Security\Http\HttpUtils;

class WebauthnListener
{
    private LoggerInterface $logger;

    
    public function __construct(private HttpUtils $httpUtils, ?LoggerInterface $logger, private RequestListener $requestListener, private CreationListener $creationListener, private array $options)
    {
        $this->logger = $logger ?? new NullLogger();
    }

    public function __invoke(RequestEvent $event): void
    {
        $this->logger->debug('Webauthn Listener called');
        $request = $event->getRequest();
        if (!$request->isMethod(Request::METHOD_POST)) {
            $this->logger->debug('The request method is not a POST. Ignored');

            return;
        }
        $content = is_string($request->getContentType()) ? $request->getContentType() : '';
        if (false === mb_strpos($content, 'json') && false === mb_strpos($request->getRequestFormat(), 'json')) {
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
        }
    }
}
