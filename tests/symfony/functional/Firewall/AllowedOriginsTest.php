<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Firewall;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Request;
use Webauthn\Tests\Bundle\Functional\WebauthnTestCase;

/**
 * @internal
 */
final class AllowedOriginsTest extends WebauthnTestCase
{
    #[Test]
    public function allowedOriginsAreAvailable(): void
    {
        //Given
        $client = static::createClient(server: [
            'HTTPS' => 'on',
        ]);

        //When
        $client->request(Request::METHOD_GET, '/.well-known/webauthn');

        //Then
        static::assertResponseIsSuccessful();
        static::assertSame(
            '{"origins":["https:\/\/localhost","https:\/\/bar.acme","https:\/\/webauthn.spomky-labs.com","https:\/\/spomky-webauthn.herokuapp.com"]}',
            $client->getResponse()
                ->getContent()
        );
    }
}
