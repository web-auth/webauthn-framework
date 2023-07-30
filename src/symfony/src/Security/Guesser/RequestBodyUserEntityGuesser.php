<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Guesser;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\Bundle\Dto\ServerPublicKeyCredentialCreationOptionsRequest;
use Webauthn\Bundle\Exception\MissingUserEntityException;
use Webauthn\Bundle\Repository\CanGenerateUserEntity;
use Webauthn\Bundle\Repository\CanRegisterUserEntity;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepositoryInterface;
use Webauthn\Exception\InvalidDataException;
use Webauthn\PublicKeyCredentialUserEntity;
use function count;

final class RequestBodyUserEntityGuesser implements UserEntityGuesser
{
    public function __construct(
        private readonly SerializerInterface $serializer,
        private readonly ValidatorInterface $validator,
        private readonly PublicKeyCredentialUserEntityRepositoryInterface $userEntityRepository,
    ) {
    }

    public function findUserEntity(Request $request): PublicKeyCredentialUserEntity
    {
        $format = method_exists(
            $request,
            'getContentTypeFormat'
        ) ? $request->getContentTypeFormat() : $request->getContentType();
        $format === 'json' || throw InvalidDataException::create($format, 'Only JSON content type allowed');
        $content = $request->getContent();

        /** @var ServerPublicKeyCredentialCreationOptionsRequest $dto */
        $dto = $this->serializer->deserialize(
            $content,
            ServerPublicKeyCredentialCreationOptionsRequest::class,
            'json'
        );
        $errors = $this->validator->validate($dto);

        if (count($errors) > 0) {
            $messages = [];
            foreach ($errors as $error) {
                $messages[] = $error->getPropertyPath() . ': ' . $error->getMessage();
            }
            throw InvalidDataException::create(null, implode("\n", $messages));
        }

        $existingUserEntity = null;
        if ($dto->username !== null) {
            $existingUserEntity = $this->userEntityRepository->findOneByUsername($dto->username);
        }
        if ($existingUserEntity !== null) {
            return $existingUserEntity;
        }

        if ($this->userEntityRepository instanceof CanGenerateUserEntity) {
            return $this->userEntityRepository->generateUserEntity($dto->username, $dto->displayName);
        }

        if (! $this->userEntityRepository instanceof CanRegisterUserEntity) {
            throw MissingUserEntityException::create('Unable to find the user entity');
        }
        if ($dto->username === null || $dto->username === '') {
            throw InvalidDataException::create($dto, 'The parameter "username" is missing or empty.');
        }
        if ($dto->displayName === null || $dto->displayName === '') {
            throw InvalidDataException::create($dto, 'The parameter "displayName" is missing or empty.');
        }

        return PublicKeyCredentialUserEntity::create(
            $dto->username,
            $this->userEntityRepository->generateNextUserEntityId(),
            $dto->displayName
        );
    }
}
