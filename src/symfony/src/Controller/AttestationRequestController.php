<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Controller;

use function count;
use const FILTER_VALIDATE_BOOLEAN;
use function is_array;
use function is_string;
use RuntimeException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Throwable;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Dto\PublicKeyCredentialCreationOptionsRequest;
use Webauthn\Bundle\Security\Guesser\UserEntityGuesser;
use Webauthn\Bundle\Security\Handler\CreationOptionsHandler;
use Webauthn\Bundle\Security\Handler\FailureHandler;
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
        private readonly UserEntityGuesser $userEntityGuesser,
        private readonly SerializerInterface $serializer,
        private readonly ValidatorInterface $validator,
        private readonly PublicKeyCredentialSourceRepository $credentialSourceRepository,
        private readonly PublicKeyCredentialCreationOptionsFactory $publicKeyCredentialCreationOptionsFactory,
        private readonly string $profile,
        private readonly OptionsStorage $optionsStorage,
        private readonly CreationOptionsHandler $creationOptionsHandler,
        private readonly FailureHandler|AuthenticationFailureHandlerInterface $failureHandler,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        try {
            $request->getContentType() === 'json' || throw new BadRequestHttpException(
                'Only JSON content type allowed'
            );
            $content = $request->getContent();
            is_string($content) || throw new BadRequestHttpException('Invalid data');

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

    private function getPublicKeyCredentialCreationOptions(
        string $content,
        PublicKeyCredentialUserEntity $userEntity
    ): PublicKeyCredentialCreationOptions {
        $excludedCredentials = $this->getCredentials($userEntity);
        $creationOptionsRequest = $this->getServerPublicKeyCredentialCreationOptionsRequest($content);
        $authenticatorSelectionData = $creationOptionsRequest->authenticatorSelection;
        $authenticatorSelection = null;
        if (is_array($authenticatorSelectionData)) {
            $authenticatorSelection = AuthenticatorSelectionCriteria::createFromArray($authenticatorSelectionData);
        } elseif ($creationOptionsRequest->userVerification !== null || $creationOptionsRequest->residentKey !== null || $creationOptionsRequest->authenticatorAttachment !== null) {
            $authenticatorSelection = AuthenticatorSelectionCriteria::create()
                ->setUserVerification(
                    $creationOptionsRequest->userVerification ?? AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED
                )
                ->setAuthenticatorAttachment($creationOptionsRequest->authenticatorAttachment);
            if ($creationOptionsRequest->residentKey !== null) {
                $authenticatorSelection->setResidentKey($creationOptionsRequest->residentKey);
            }
            if ($creationOptionsRequest->requireResidentKey !== null) {
                $authenticatorSelection->setRequireResidentKey(
                    filter_var($creationOptionsRequest->requireResidentKey, FILTER_VALIDATE_BOOLEAN)
                );
            }
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
    ): PublicKeyCredentialCreationOptionsRequest {
        $data = $this->serializer->deserialize($content, PublicKeyCredentialCreationOptionsRequest::class, 'json');
        $data instanceof PublicKeyCredentialCreationOptionsRequest || throw new BadRequestHttpException(
            'Invalid data'
        );
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
