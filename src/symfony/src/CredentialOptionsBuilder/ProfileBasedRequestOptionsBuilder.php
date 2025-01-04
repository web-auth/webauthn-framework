<?php

declare(strict_types=1);

namespace Webauthn\Bundle\CredentialOptionsBuilder;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\Bundle\Dto\ServerPublicKeyCredentialRequestOptionsRequest;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepositoryInterface;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\FakeCredentialGenerator;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;
use function count;
use function is_array;
use function sprintf;

final class ProfileBasedRequestOptionsBuilder implements PublicKeyCredentialRequestOptionsBuilder
{
    public function __construct(
        private readonly SerializerInterface $serializer,
        private readonly ValidatorInterface $validator,
        private readonly PublicKeyCredentialUserEntityRepositoryInterface $userEntityRepository,
        private readonly PublicKeyCredentialSourceRepository|PublicKeyCredentialSourceRepositoryInterface $credentialSourceRepository,
        private readonly PublicKeyCredentialRequestOptionsFactory $publicKeyCredentialRequestOptionsFactory,
        private readonly string $profile,
        private readonly null|FakeCredentialGenerator $fakeCredentialGenerator = null,
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
        $optionsRequest = $this->getServerPublicKeyCredentialRequestOptionsRequest($content);
        $extensions = null;
        if (is_array($optionsRequest->extensions)) {
            $extensions = AuthenticationExtensionsClientInputs::create(array_map(
                static fn (string $name, mixed $data): AuthenticationExtension => AuthenticationExtension::create(
                    $name,
                    $data
                ),
                array_keys($optionsRequest->extensions),
                $optionsRequest->extensions
            ));
        }
        $userEntity = $optionsRequest->username === null ? null : $this->userEntityRepository->findOneByUsername(
            $optionsRequest->username
        );

        $allowedCredentials = match (true) {
            $userEntity === null && $optionsRequest->username === null, $userEntity === null && $optionsRequest->username !== null && $this->fakeCredentialGenerator === null => [],
            $userEntity === null && $optionsRequest->username !== null && $this->fakeCredentialGenerator !== null => $this->fakeCredentialGenerator->generate(
                $request,
                $optionsRequest->username
            ),
            default => $this->getCredentials($userEntity),
        };

        return $this->publicKeyCredentialRequestOptionsFactory->create(
            $this->profile,
            $allowedCredentials,
            $optionsRequest->userVerification,
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
