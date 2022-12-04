<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Firewall;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @internal
 */
final class NonSecuredAreaTest extends WebTestCase
{
    /**
     * @test
     */
    public function aClientWantsToAccessOnNonSecuredResource(): void
    {
        $client = static::createClient();
        $client->request('GET', '/', [], [], [
            'HTTPS' => 'on',
        ]);

        static::assertResponseIsSuccessful();
        static::assertSame('Home', $client->getResponse()->getContent());
    }
}
