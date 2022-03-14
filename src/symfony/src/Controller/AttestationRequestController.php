<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Controller;

use Assert\Assertion;
use function count;
use function is_array;
use RuntimeException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Throwable;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Dto\AdditionalPublicKeyCredentialCreationOptionsRequest;
use Webauthn\Bundle\Security\Guesser\UserEntityGuesser;
use Webauthn\Bundle\Security\Handler\CreationOptionsHandler;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

final class AttestationRequestController
{
    public function __construct(
        private UserEntityGuesser $userEntityGuesser,
        private SerializerInterface $serializer,
        private ValidatorInterface $validator,
        private PublicKeyCredentialSourceRepository $credentialSourceRepository,
        private PublicKeyCredentialCreationOptionsFactory $publicKeyCredentialCreationOptionsFactory,
        private string $profile,
        private OptionsStorage $optionsStorage,
        private CreationOptionsHandler $creationOptionsHandler,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        try {
            Assertion::eq('json', $request->getContentType(), 'Only JSON content type allowed');
            $content = $request->getContent();
            Assertion::string($content, 'Invalid data');

            $userEntity = $this->userEntityGuesser->findUserEntity($request);
            $publicKeyCredentialCreationOptions = $this->getPublicKeyCredentialCreationOptions(
                $content,
                $userEntity
            );

            $response = $this->creationOptionsHandler->onCreationOptions(
                $publicKeyCredentialCreationOptions,
                $userEntity
            );
            $this->optionsStorage->store(Item::create($publicKeyCredentialCreationOptions, $userEntity));

            return $response;
        } catch (Throwable $throwable) {
            return new JsonResponse([
                'status' => 'error',
                'errorMessage' => $throwable->getMessage(),
            ], 400);
        }
    }

    /**
     * @return PublicKeyCredentialDescriptor[]
     */
    private function getCredentials(PublicKeyCredentialUserEntity $userEntity): array
    {
        $credentialSources = $this->credentialSourceRepository->findAllForUserEntity($userEntity);

        return array_map(static function (PublicKeyCredentialSource $credential): PublicKeyCredentialDescriptor {
            return $credential->getPublicKeyCredentialDescriptor();
        }, $credentialSources);
    }

    private function getPublicKeyCredentialCreationOptions(
        string $content,
        PublicKeyCredentialUserEntity $userEntity
    ): PublicKeyCredentialCreationOptions {
        $excludedCredentials = $this->getCredentials($userEntity);
        $creationOptionsRequest = $this->getServerPublicKeyCredentialCreationOptionsRequest($content);
        $authenticatorSelection = $creationOptionsRequest->authenticatorSelection;
        if (is_array($authenticatorSelection)) {
            $authenticatorSelection = AuthenticatorSelectionCriteria::createFromArray($authenticatorSelection);
        }
        $extensions = $creationOptionsRequest->extensions;
        if (is_array($extensions)) {
            $extensions = AuthenticationExtensionsClientInputs::createFromArray($extensions);
        }

        return $this->publicKeyCredentialCreationOptionsFactory->create(
            $this->profile,
            $userEntity,
            $excludedCredentials,
            $authenticatorSelection,
            $creationOptionsRequest->attestation,
            $extensions
        );
    }

    private function getServerPublicKeyCredentialCreationOptionsRequest(
        string $content
    ): AdditionalPublicKeyCredentialCreationOptionsRequest {
        $data = $this->serializer->deserialize(
            $content,
            AdditionalPublicKeyCredentialCreationOptionsRequest::class,
            'json'
        );
        Assertion::isInstanceOf($data, AdditionalPublicKeyCredentialCreationOptionsRequest::class, 'Invalid data');
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
}
