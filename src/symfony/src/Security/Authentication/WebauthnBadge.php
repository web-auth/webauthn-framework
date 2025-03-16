<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Authentication;

use LogicException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\BadgeInterface;
use Webauthn\AuthenticatorResponse;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use function sprintf;

final class WebauthnBadge implements BadgeInterface
{
    private bool $isResolved = false;

    private AuthenticatorResponse $authenticatorResponse;

    private PublicKeyCredentialOptions $publicKeyCredentialOptions;

    private PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity;

    private PublicKeyCredentialSource $publicKeyCredentialSource;

    private UserInterface $user;

    /**
     * @var callable|null
     */
    private $userLoader;

    public function __construct(
        public readonly string $host,
        public readonly string $response,
        ?callable $userLoader = null,
        private readonly ?array $attributes = null,
        public bool $allowRegistration = false
    ) {
        $this->userLoader = $userLoader;
    }

    public function isResolved(): bool
    {
        return $this->isResolved;
    }

    public function getAuthenticatorResponse(): AuthenticatorResponse
    {
        if (! $this->isResolved) {
            throw new LogicException('The badge is not resolved.');
        }
        return $this->authenticatorResponse;
    }

    public function getPublicKeyCredentialOptions(): PublicKeyCredentialOptions
    {
        if (! $this->isResolved) {
            throw new LogicException('The badge is not resolved.');
        }
        return $this->publicKeyCredentialOptions;
    }

    public function getPublicKeyCredentialUserEntity(): PublicKeyCredentialUserEntity
    {
        if (! $this->isResolved) {
            throw new LogicException('The badge is not resolved.');
        }
        return $this->publicKeyCredentialUserEntity;
    }

    public function getPublicKeyCredentialSource(): PublicKeyCredentialSource
    {
        if (! $this->isResolved) {
            throw new LogicException('The badge is not resolved.');
        }
        return $this->publicKeyCredentialSource;
    }

    public function getUser(): UserInterface
    {
        if (! $this->isResolved) {
            throw new LogicException('The badge is not resolved.');
        }
        return $this->user;
    }

    public function markResolved(
        AuthenticatorResponse $authenticatorResponse,
        PublicKeyCredentialOptions $publicKeyCredentialOptions,
        PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity,
        PublicKeyCredentialSource $publicKeyCredentialSource,
    ): void {
        if ($this->userLoader === null) {
            throw new LogicException(sprintf(
                'No user loader is configured, did you forget to register the "%s" listener?',
                WebauthnBadgeListener::class
            ));
        }
        $this->authenticatorResponse = $authenticatorResponse;
        $this->publicKeyCredentialOptions = $publicKeyCredentialOptions;
        $this->publicKeyCredentialUserEntity = $publicKeyCredentialUserEntity;
        $this->publicKeyCredentialSource = $publicKeyCredentialSource;
        $user = ($this->userLoader)($publicKeyCredentialUserEntity->name, $this->attributes);
        if ($user === null) {
            $exception = new UserNotFoundException();
            $exception->setUserIdentifier($publicKeyCredentialSource->userHandle);

            throw $exception;
        }
        $this->user = $user;
        $this->isResolved = true;
    }

    public function setUserLoader(callable $userLoader): void
    {
        $this->userLoader = $userLoader;
    }

    public function getUserLoader(): ?callable
    {
        return $this->userLoader;
    }
}
