<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Controller;

use function count;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Throwable;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\Bundle\Dto\ServerPublicKeyCredentialRequestOptionsRequest;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Security\Handler\FailureHandler;
use Webauthn\Bundle\Security\Handler\RequestOptionsHandler;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

final class AssertionRequestController
{
    public function __construct(
        private readonly SerializerInterface $serializer,
        private readonly ValidatorInterface $validator,
        private readonly PublicKeyCredentialUserEntityRepository $userEntityRepository,
        private readonly PublicKeyCredentialSourceRepository $credentialSourceRepository,
        private readonly PublicKeyCredentialRequestOptionsFactory $publicKeyCredentialRequestOptionsFactory,
        private readonly string $profile,
        private readonly OptionsStorage $optionsStorage,
        private readonly RequestOptionsHandler $optionsHandler,
        private readonly FailureHandler|AuthenticationFailureHandlerInterface $failureHandler,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        try {
            $request->getContentType() === 'json' || throw new BadRequestHttpException(
                'Only JSON content type allowed'
            );
            $content = $request->getContent();
            $creationOptionsRequest = $this->getServerPublicKeyCredentialRequestOptionsRequest($content);
            $extensions = $creationOptionsRequest->extensions !== null ? AuthenticationExtensionsClientInputs::createFromArray(
                $creationOptionsRequest->extensions
            ) : null;
            $userEntity = $creationOptionsRequest->username === null ? null : $this->userEntityRepository->findOneByUsername(
                $creationOptionsRequest->username
            );
            $allowedCredentials = $userEntity === null ? [] : $this->getCredentials($userEntity);
            $publicKeyCredentialRequestOptions = $this->publicKeyCredentialRequestOptionsFactory->create(
                $this->profile,
                $allowedCredentials,
                $creationOptionsRequest->userVerification,
                $extensions
            );

            $response = $this->optionsHandler->onRequestOptions($publicKeyCredentialRequestOptions, $userEntity);
            $this->optionsStorage->store(Item::create($publicKeyCredentialRequestOptions, $userEntity));

            return $response;
        } catch (Throwable $throwable) {
            $this->logger->error($throwable->getMessage());
            if ($this->failureHandler instanceof AuthenticationFailureHandlerInterface) {
                return $this->failureHandler->onAuthenticationFailure(
                    $request,
                    new AuthenticationException($throwable->getMessage(), $throwable->getCode(), $throwable)
                );
            }

            return $this->failureHandler->onFailure($request, $throwable);
        }
    }

    /**
     * @return PublicKeyCredentialDescriptor[]
     */
    private function getCredentials(PublicKeyCredentialUserEntity $userEntity): array
    {
        $credentialSources = $this->credentialSourceRepository->findAllForUserEntity($userEntity);

        return array_map(
            static fn (PublicKeyCredentialSource $credential): PublicKeyCredentialDescriptor => $credential->getPublicKeyCredentialDescriptor(),
            $credentialSources
        );
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
        $data instanceof ServerPublicKeyCredentialRequestOptionsRequest || throw new BadRequestHttpException(
            'Invalid data'
        );
        $errors = $this->validator->validate($data);
        if (count($errors) > 0) {
            $messages = [];
            foreach ($errors as $error) {
                $messages[] = $error->getPropertyPath() . ': ' . $error->getMessage();
            }
            throw new BadRequestHttpException(implode("\n", $messages));
        }

        return $data;
    }
}
