<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Tests\Functional\Firewall;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group functional
 *
 * @internal
 */
class NonSecuredAreaTest extends WebTestCase
{
    /**
     * @test
     */
    public function aClientWantsToAccessOnNonSecuredResource(): void
    {
        $client = static::createClient();
        $client->request('GET', '/', [], [], ['HTTPS' => 'on']);

        static::assertEquals(200, $client->getResponse()->getStatusCode());
        static::assertEquals('Home', $client->getResponse()->getContent());
    }
}
