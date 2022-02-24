<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\MetadataService;

use function count;
use function in_array;
use function is_array;
use function is_object;
use Nyholm\Psr7\Factory\Psr17Factory;
use ReflectionMethod;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Throwable;
use Webauthn\MetadataService\MetadataService;
use Webauthn\MetadataService\MetadataStatementFetcher;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\Tests\MockedMappedResponseTrait;
use Webauthn\Tests\MockedRequestTrait;

/**
 * @internal
 */
final class MetadataServiceTest extends KernelTestCase
{
    use MockedRequestTrait;
    use MockedMappedResponseTrait;

    /**
     * @test
     */
    public function theMetadataTOCPayloadCanBeRetrieved(): void
    {
        self::bootKernel();

        $client = self::getContainer()->get('httplug.client.mock');
        $this->prepareResponsesMap($client);

        $service = new MetadataService('https://fidoalliance.co.nz', $client, new Psr17Factory());
        $data = $service->getMetadataTOCPayload();
        $entries = $data->getEntries();
        static::assertCount(42, $entries);
        static::assertSame('2019-08-30', $data->getNextUpdate());
        static::assertSame(18, $data->getNo());
        static::assertSame(
            'Metadata Legal Header: Version 1.00.　Date: May 21, 2018.  To access, view and use any Metadata Statements or the TOC file (“METADATA”) from the MDS, You must be bound by the latest FIDO Alliance Metadata Usage Terms that can be found at http://mds2.fidoalliance.org/ . If you already have a valid token, access the above URL attaching your token such as http://mds2.fidoalliance.org?token=YOUR-VALID-TOKEN.  If You have not entered into the agreement, please visit the registration site found at http://fidoalliance.org/MDS/ and enter into the agreement and obtain a valid token.  You must not redistribute this file to any third party. Removal of this Legal Header or modifying any part of this file renders this file invalid.  The integrity of this file as originally provided from the MDS is validated by the hash value of this file that is recorded in the MDS. The use of invalid files is strictly prohibited. If the version number for the Legal Header is updated from Version 1.00, the METADATA below may also be updated or may not be available. Please use the METADATA with the Legal Header with the latest version number.  Dated: 2018-05-21 Version LH-1.00',
            $data->getLegalHeader()
        );

        foreach ($entries as $entry) {
            try {
                $ms = $service->getMetadataStatementFor($entry);
                $this->callObjectMethods($ms);
            } catch (Throwable) {
                continue;
            }
        }

        $client->reset();
    }

    /**
     * @test
     */
    public function aMetadataStatementFromAnotherUriCanBeRetrieved(): void
    {
        self::bootKernel();

        $client = self::getContainer()->get('httplug.client.mock');
        $this->prepareResponsesMap($client);

        $ms = MetadataStatementFetcher::fetchMetadataStatement(
            'https://raw.githubusercontent.com/solokeys/solo/2.1.0/metadata/Solo-FIDO2-CTAP2-Authenticator.json',
            false,
            $client,
            new Psr17Factory()
        );

        static::assertSame('8876631b-d4a0-427f-5773-0ec71c9e0279', $ms->getAAguid());
        static::assertSame('Solo Secp256R1 FIDO2 CTAP2 Authenticator', $ms->getDescription());
        static::assertSame([], $ms->getAlternativeDescriptions());
        static::assertSame('FIDOV2', $ms->getAssertionScheme());
        $this->callObjectMethods($ms);
    }

    /**
     * @test
     */
    public function aMetadataStatementCanBeFoundByTheRepository(): void
    {
        self::bootKernel();

        $client = self::getContainer()->get('httplug.client.mock');
        $this->prepareResponsesMap($client);

        /** @var MetadataStatementRepository $repository */
        $repository = static::$container->get(MetadataStatementRepository::class);
        $ms = $repository->findOneByAAGUID('8876631b-d4a0-427f-5773-0ec71c9e0279');

        static::assertNotNull($ms);
        static::assertSame('8876631b-d4a0-427f-5773-0ec71c9e0279', $ms->getAAguid());
        static::assertSame('Solo Secp256R1 FIDO2 CTAP2 Authenticator', $ms->getDescription());
        static::assertSame([], $ms->getAlternativeDescriptions());
        static::assertSame('FIDOV2', $ms->getAssertionScheme());
    }

    protected function getResponsesMap(): array
    {
        return [];
    }

    /**
     * @param object $object
     */
    private function callObjectMethods($object): void
    {
        $availableMethods = get_class_methods($object);
        $availableMethods = array_filter($availableMethods, static function ($method) use ($object): bool {
            $classMethod = new ReflectionMethod($object, $method);

            return ! in_array(
                $method,
                ['createFromArray', 'create', '__construct', 'jsonSerialize'],
                true
            ) && count($classMethod->getParameters()) === 0;
        });
        foreach ($availableMethods as $method) {
            $value = $object->{$method}();
            switch (true) {
                case is_object($value):
                    $this->callObjectMethods($value);
                    break;
                case is_array($value):
                    foreach ($value as $item) {
                        if (is_object($item)) {
                            $this->callObjectMethods($item);
                        }
                    }
                    break;
                default:
                    break;
            }
        }
    }
}
