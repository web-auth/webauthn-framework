<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Security\Guesser;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\ConstraintViolationList;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\Bundle\Dto\ServerPublicKeyCredentialCreationOptionsRequest;
use Webauthn\Bundle\Exception\MissingUserEntityException;
use Webauthn\Bundle\Repository\CanGenerateUserEntity;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepositoryInterface;
use Webauthn\Bundle\Security\Guesser\RequestBodyUserEntityGuesser;
use Webauthn\Exception\InvalidDataException;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * The body of a registration options request is not authenticated: whatever username it names, the guesser must never
 * return the entity of an existing account, whose user handle would then be used for the new credential.
 *
 * @internal
 */
final class RequestBodyUserEntityGuesserTest extends TestCase
{
    #[Test]
    public function aTakenUsernameGetsANewUserEntity(): void
    {
        $repository = $this->repositoryGeneratingRandomUserHandles(
            PublicKeyCredentialUserEntity::create('admin', 'foo', 'Foo BAR')
        );

        $userEntity = $this->guesser($repository, 'admin', 'Not Admin')
            ->findUserEntity($this->jsonRequest());

        static::assertSame('admin', $userEntity->name);
        static::assertSame('Not Admin', $userEntity->displayName);
        static::assertNotSame('foo', $userEntity->id);
    }

    #[Test]
    public function aGeneratedUserHandleThatIsAlreadyInUseIsRefused(): void
    {
        $repository = $this->repositoryDerivingUserHandlesFromUsernames(
            PublicKeyCredentialUserEntity::create('admin@example.com', 'admin@example.com', 'Admin')
        );

        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('The generated user handle is already in use');

        $this->guesser($repository, 'admin@example.com', 'Not Admin')
            ->findUserEntity($this->jsonRequest());
    }

    #[Test]
    public function aRepositoryThatCannotGenerateUserEntitiesIsRefusedEvenForATakenUsername(): void
    {
        $repository = $this->repositoryWithoutGeneration(PublicKeyCredentialUserEntity::create('admin', 'foo', 'Foo BAR'));

        $this->expectException(MissingUserEntityException::class);

        $this->guesser($repository, 'admin', 'Not Admin')
            ->findUserEntity($this->jsonRequest());
    }

    private function guesser(
        PublicKeyCredentialUserEntityRepositoryInterface $repository,
        string $username,
        string $displayName
    ): RequestBodyUserEntityGuesser {
        $dto = new ServerPublicKeyCredentialCreationOptionsRequest();
        $dto->username = $username;
        $dto->displayName = $displayName;
        $serializer = static::createStub(SerializerInterface::class);
        $serializer->method('deserialize')
            ->willReturn($dto);
        $validator = static::createStub(ValidatorInterface::class);
        $validator->method('validate')
            ->willReturn(new ConstraintViolationList());

        return new RequestBodyUserEntityGuesser($serializer, $validator, $repository);
    }

    private function jsonRequest(): Request
    {
        return Request::create('/register/options', Request::METHOD_POST, [], [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], '{}');
    }

    private function repositoryGeneratingRandomUserHandles(
        PublicKeyCredentialUserEntity $existingUser
    ): PublicKeyCredentialUserEntityRepositoryInterface {
        return new class($existingUser) implements PublicKeyCredentialUserEntityRepositoryInterface, CanGenerateUserEntity {
            public function __construct(
                private readonly PublicKeyCredentialUserEntity $existingUser
            ) {
            }

            public function findOneByUsername(string $username): ?PublicKeyCredentialUserEntity
            {
                return $username === $this->existingUser->name ? $this->existingUser : null;
            }

            public function findOneByUserHandle(string $userHandle): ?PublicKeyCredentialUserEntity
            {
                return $userHandle === $this->existingUser->id ? $this->existingUser : null;
            }

            public function generateUserEntity(?string $username, ?string $displayName): PublicKeyCredentialUserEntity
            {
                return PublicKeyCredentialUserEntity::create(
                    $username ?? 'anonymous',
                    random_bytes(32),
                    $displayName ?? 'Anonymous'
                );
            }
        };
    }

    /**
     * A repository that uses the username as user handle, which the WebAuthn specification advises against: the
     * entity it generates for a taken username carries the user handle of that account.
     */
    private function repositoryDerivingUserHandlesFromUsernames(
        PublicKeyCredentialUserEntity $existingUser
    ): PublicKeyCredentialUserEntityRepositoryInterface {
        return new class($existingUser) implements PublicKeyCredentialUserEntityRepositoryInterface, CanGenerateUserEntity {
            public function __construct(
                private readonly PublicKeyCredentialUserEntity $existingUser
            ) {
            }

            public function findOneByUsername(string $username): ?PublicKeyCredentialUserEntity
            {
                return $username === $this->existingUser->name ? $this->existingUser : null;
            }

            public function findOneByUserHandle(string $userHandle): ?PublicKeyCredentialUserEntity
            {
                return $userHandle === $this->existingUser->id ? $this->existingUser : null;
            }

            public function generateUserEntity(?string $username, ?string $displayName): PublicKeyCredentialUserEntity
            {
                return PublicKeyCredentialUserEntity::create(
                    $username ?? 'anonymous',
                    $username ?? 'anonymous',
                    $displayName ?? 'Anonymous'
                );
            }
        };
    }

    private function repositoryWithoutGeneration(
        PublicKeyCredentialUserEntity $existingUser
    ): PublicKeyCredentialUserEntityRepositoryInterface {
        return new class($existingUser) implements PublicKeyCredentialUserEntityRepositoryInterface {
            public function __construct(
                private readonly PublicKeyCredentialUserEntity $existingUser
            ) {
            }

            public function findOneByUsername(string $username): ?PublicKeyCredentialUserEntity
            {
                return $username === $this->existingUser->name ? $this->existingUser : null;
            }

            public function findOneByUserHandle(string $userHandle): ?PublicKeyCredentialUserEntity
            {
                return $userHandle === $this->existingUser->id ? $this->existingUser : null;
            }
        };
    }
}
