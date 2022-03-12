<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Listener;

use Assert\Assertion;
use function count;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Throwable;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\Bundle\Dto\ServerPublicKeyCredentialRequestOptionsRequest;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnToken;
use Webauthn\Bundle\Security\Handler\RequestOptionsHandler;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Security\Storage\StoredData;
use Webauthn\Bundle\Security\WebauthnFirewallConfig;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

class RequestOptionsListener implements EventSubscriberInterface
{
    // Execute right before ContextListener, which is serializing the security token into the session
    public const RESPONSE_LISTENER_PRIORITY = 1;

    private LoggerInterface $logger;

    public function __construct(
        private WebauthnFirewallConfig $firewallConfig,
        private AuthenticationFailureHandlerInterface $authenticationFailureHandler,
        private RequestOptionsHandler $optionsHandler,
        private OptionsStorage $optionsStorage,
        private SerializerInterface $serializer,
        private ValidatorInterface $validator,
        private PublicKeyCredentialRequestOptionsFactory $publicKeyCredentialRequestOptionsFactory,
        private PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository,
        private PublicKeyCredentialUserEntityRepository $userEntityRepository,
        private TokenStorageInterface $tokenStorage,
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    public function onKernelResponse(RequestEvent $event): void
    {
        if (! $event->isMainRequest()) {
            return;
        }
        $request = $event->getRequest();

        try {
            $content = $request->getContent();
            Assertion::string($content, 'Invalid data');
            $creationOptionsRequest = $this->getServerPublicKeyCredentialRequestOptionsRequest($content);
            $extensions = $creationOptionsRequest->extensions !== null ? AuthenticationExtensionsClientInputs::createFromArray(
                $creationOptionsRequest->extensions
            ) : null;
            $userEntity = $creationOptionsRequest->username === null ? null : $this->userEntityRepository->findOneByUsername(
                $creationOptionsRequest->username
            );
            $allowedCredentials = $userEntity !== null ? $this->getCredentials($userEntity) : [];
            $publicKeyCredentialRequestOptions = $this->publicKeyCredentialRequestOptionsFactory->create(
                $this->firewallConfig->getAuthenticationProfile(),
                $allowedCredentials,
                $creationOptionsRequest->userVerification,
                $extensions
            );
            $response = $this->optionsHandler->onRequestOptions($publicKeyCredentialRequestOptions, $userEntity);
            $this->optionsStorage->store(
                $request,
                new StoredData($publicKeyCredentialRequestOptions, $userEntity),
                $response
            );
        } catch (Throwable $e) {
            $this->logger->error('An error occurred', [
                'exception' => $e,
            ]);
            $response = $this->onAssertionFailure($request, new AuthenticationException($e->getMessage(), 0, $e));
        }

        $event->setResponse($response);
    }

    /**
     * {@inheritdoc}
     */
    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::RESPONSE => ['onKernelResponse', self::RESPONSE_LISTENER_PRIORITY],
        ];
    }

    private function onAssertionFailure(Request $request, AuthenticationException $failed): Response
    {
        $token = $this->tokenStorage->getToken();
        if ($token instanceof WebauthnToken && $this->firewallConfig->getFirewallName() === $token->getFirewallName()) {
            $this->tokenStorage->setToken(null);
        }

        return $this->authenticationFailureHandler->onAuthenticationFailure($request, $failed);
    }

    private function getServerPublicKeyCredentialRequestOptionsRequest(
        string $content
    ): ServerPublicKeyCredentialRequestOptionsRequest {
        $data = $this->serializer->deserialize(
            $content,
            ServerPublicKeyCredentialRequestOptionsRequest::class,
            'json',
            [
                AbstractObjectNormalizer::DISABLE_TYPE_ENFORCEMENT => true,
            ]
        );
        Assertion::isInstanceOf($data, ServerPublicKeyCredentialRequestOptionsRequest::class, 'Invalid data');
        $errors = $this->validator->validate($data);
        if (count($errors) > 0) {
            $messages = [];
            foreach ($errors as $error) {
                $messages[] = $error->getPropertyPath() . ': ' . $error->getMessage();
            }
            throw new RuntimeException(implode("\n", $messages));
        }

        return $data;
    }

    /**
     * @return PublicKeyCredentialDescriptor[]
     */
    private function getCredentials(PublicKeyCredentialUserEntity $userEntity): array
    {
        $credentialSources = $this->publicKeyCredentialSourceRepository->findAllForUserEntity($userEntity);

        return array_map(static function (PublicKeyCredentialSource $credential): PublicKeyCredentialDescriptor {
            return $credential->getPublicKeyCredentialDescriptor();
        }, $credentialSources);
    }
}
