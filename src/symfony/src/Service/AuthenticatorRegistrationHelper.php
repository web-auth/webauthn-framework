<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use Assert\Assertion;
use function count;
use RuntimeException;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Dto\AdditionalPublicKeyCredentialCreationOptionsRequest;
use Webauthn\Bundle\Security\Storage\SessionStorage;
use Webauthn\Bundle\Security\Storage\StoredData;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * @deprecated This class is deprecated and will be removed in 4.0
 */
class AuthenticatorRegistrationHelper
{
    public function __construct(
        private PublicKeyCredentialCreationOptionsFactory $publicKeyCredentialCreationOptionsFactory,
        private SerializerInterface $serializer,
        private ValidatorInterface $validator,
        private PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository,
        private PublicKeyCredentialLoader $publicKeyCredentialLoader,
        private AuthenticatorAttestationResponseValidator $authenticatorAttestationResponseValidator,
        private SessionStorage $optionsStorage,
        private HttpMessageFactoryInterface $httpMessageFactory,
        private array $securedRelyingPartyId = []
    ) {
    }

    public function generateOptions(
        PublicKeyCredentialUserEntity $userEntity,
        Request $request,
        string $profile = 'default'
    ): PublicKeyCredentialCreationOptions {
        $content = $request->getContent();
        Assertion::string($content, 'Invalid data');
        $creationOptionsRequest = $this->getAdditionalPublicKeyCredentialCreationOptionsRequest($content);
        $authenticatorSelection = $creationOptionsRequest->authenticatorSelection !== null ? AuthenticatorSelectionCriteria::createFromArray(
            $creationOptionsRequest->authenticatorSelection
        ) : null;
        $extensions = $creationOptionsRequest->extensions !== null ? AuthenticationExtensionsClientInputs::createFromArray(
            $creationOptionsRequest->extensions
        ) : null;
        $publicKeyCredentialCreationOptions = $this->publicKeyCredentialCreationOptionsFactory->create(
            $profile,
            $userEntity,
            $this->getUserAuthenticatorList($userEntity),
            $authenticatorSelection,
            $creationOptionsRequest->attestation,
            $extensions
        );
        $this->optionsStorage->store($request, new StoredData($publicKeyCredentialCreationOptions, $userEntity));

        return $publicKeyCredentialCreationOptions;
    }

    public function validateResponse(PublicKeyCredentialUserEntity $user, Request $request): PublicKeyCredentialSource
    {
        $storedData = $this->optionsStorage->get($request);
        $assertion = $request->getContent();
        Assertion::string($assertion, 'Invalid assertion');
        $assertion = trim($assertion);
        $publicKeyCredential = $this->publicKeyCredentialLoader->load($assertion);
        $response = $publicKeyCredential->getResponse();
        if (! $response instanceof AuthenticatorAttestationResponse) {
            throw new AuthenticationException('Invalid assertion');
        }

        $psr7Request = $this->httpMessageFactory->createRequest($request);

        $options = $storedData->getPublicKeyCredentialOptions();
        Assertion::isInstanceOf($options, PublicKeyCredentialCreationOptions::class, 'Invalid options');
        $userEntity = $storedData->getPublicKeyCredentialUserEntity();
        Assertion::notNull($userEntity, 'Invalid user');
        Assertion::eq($user->getId(), $userEntity->getId(), PublicKeyCredentialUserEntity::class, 'Invalid user');

        $publicKeyCredentialSource = $this->authenticatorAttestationResponseValidator->check(
            $response,
            $options,
            $psr7Request,
            $this->securedRelyingPartyId
        );
        $this->publicKeyCredentialSourceRepository->saveCredentialSource($publicKeyCredentialSource);

        return $publicKeyCredentialSource;
    }

    private function getAdditionalPublicKeyCredentialCreationOptionsRequest(
        string $content
    ): AdditionalPublicKeyCredentialCreationOptionsRequest {
        $data = $this->serializer->deserialize(
            $content,
            AdditionalPublicKeyCredentialCreationOptionsRequest::class,
            'json',
            [
                AbstractObjectNormalizer::DISABLE_TYPE_ENFORCEMENT => true,
            ]
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

    /**
     * @return PublicKeyCredentialDescriptor[]
     */
    private function getUserAuthenticatorList(PublicKeyCredentialUserEntity $userEntity): array
    {
        $list = $this->publicKeyCredentialSourceRepository->findAllForUserEntity($userEntity);

        return array_map(
            static function (PublicKeyCredentialSource $publicKeyCredentialSource): PublicKeyCredentialDescriptor {
                return $publicKeyCredentialSource->getPublicKeyCredentialDescriptor();
            },
            $list
        );
    }
}
