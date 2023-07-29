<?php

declare(strict_types=1);

namespace Webauthn\Bundle\CredentialOptionsBuilder;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\Bundle\Dto\ServerPublicKeyCredentialRequestOptionsRequest;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepositoryInterface;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;
use function count;

final class ProfileBasedRequestOptionsBuilder implements PublicKeyCredentialRequestOptionsBuilder
{
    public function __construct(
        private readonly SerializerInterface $serializer,
        private readonly ValidatorInterface $validator,
        private readonly PublicKeyCredentialUserEntityRepositoryInterface $userEntityRepository,
        private readonly PublicKeyCredentialSourceRepository|PublicKeyCredentialSourceRepositoryInterface $credentialSourceRepository,
        private readonly PublicKeyCredentialRequestOptionsFactory $publicKeyCredentialRequestOptionsFactory,
        private readonly string $profile,
    ) {
        if (! $this->credentialSourceRepository instanceof PublicKeyCredentialSourceRepositoryInterface) {
            trigger_deprecation(
                'web-auth/webauthn-symfony-bundle',
                '4.6.0',
                sprintf(
                    'Since 4.6.0, the parameter "$credentialSourceRepository" expects an instance of "%s". Please implement that interface instead of "%s".',
                    PublicKeyCredentialSourceRepositoryInterface::class,
                    PublicKeyCredentialSourceRepository::class
                )
            );
        }
    }

    public function getFromRequest(
        Request $request,
        ?PublicKeyCredentialUserEntity &$userEntity = null
    ): PublicKeyCredentialRequestOptions {
        $format = method_exists(
            $request,
            'getContentTypeFormat'
        ) ? $request->getContentTypeFormat() : $request->getContentType();
        $format === 'json' || throw new BadRequestHttpException('Only JSON content type allowed');
        $content = $request->getContent();
        $creationOptionsRequest = $this->getServerPublicKeyCredentialRequestOptionsRequest($content);
        $extensions = $creationOptionsRequest->extensions !== null ? AuthenticationExtensionsClientInputs::createFromArray(
            $creationOptionsRequest->extensions
        ) : null;
        $userEntity = $creationOptionsRequest->username === null ? null : $this->userEntityRepository->findOneByUsername(
            $creationOptionsRequest->username
        );
        $allowedCredentials = $userEntity === null ? [] : $this->getCredentials($userEntity);
        return $this->publicKeyCredentialRequestOptionsFactory->create(
            $this->profile,
            $allowedCredentials,
            $creationOptionsRequest->userVerification,
            $extensions
        );
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
