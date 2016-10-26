<?php declare(strict_types=1);

namespace ApiClients\Tests\Foundation\Cache\Middleware;

use ApiClients\Foundation\Oauth1\Middleware\Oauth1Middleware;
use ApiClients\Foundation\Oauth1\Options;
use ApiClients\Tools\TestUtilities\TestCase;
use GuzzleHttp\Psr7\Request;
use JacobKiers\OAuth\Consumer\Consumer;
use JacobKiers\OAuth\SignatureMethod\HmacSha1;
use JacobKiers\OAuth\Token\Token;
use Prophecy\Argument;
use Psr\Http\Message\RequestInterface;
use function Clue\React\Block\await;
use React\EventLoop\Factory;
use function React\Promise\resolve;

class OauthMiddlewareTest extends TestCase
{
    public function providerIncompleteRequestOptions()
    {
        yield [
            [],
        ];
        yield [
            [
                Oauth1Middleware::class => [],
            ],
        ];
        yield [
            [
                Oauth1Middleware::class => [
                    Options::CONSUMER => 'consumer',
                ],
            ],
        ];
        yield [
            [
                Oauth1Middleware::class => [
                    Options::CONSUMER => new Consumer('key', 'secret'),
                ],
            ],
        ];
        yield [
            [
                Oauth1Middleware::class => [
                    Options::CONSUMER => new Consumer('key', 'secret'),
                    Options::TOKEN => 'token',
                ],
            ],
        ];
        yield [
            [
                Oauth1Middleware::class => [
                    Options::CONSUMER => new Consumer('key', 'secret'),
                    Options::TOKEN => new Token('key', 'secret'),
                ],
            ],
        ];
        yield [
            [
                Oauth1Middleware::class => [
                    Options::CONSUMER => new Consumer('key', 'secret'),
                    Options::TOKEN => new Token('key', 'secret'),
                    Options::SIGNATURE_METHOD => 'signature_method',
                ],
            ],
        ];
    }

    /**
     * @dataProvider providerIncompleteRequestOptions
     */
    public function testIncompleteRequestOptions(array $options)
    {
        $loop = Factory::create();
        $request = $this->prophesize(RequestInterface::class)->reveal();

        $middleware = new Oauth1Middleware($loop);
        $result = await($middleware->pre($request, $options), $loop);

        $this->assertSame($request, $result);
    }

    public function testRequest()
    {
        $options = [
            Oauth1Middleware::class => [
                Options::CONSUMER => new Consumer('key', 'secret'),
                Options::TOKEN => new Token('key', 'secret'),
                Options::SIGNATURE_METHOD => new HmacSha1(),
            ],
        ];
        $loop = Factory::create();
        $request = new Request(
            'GET',
            'https://example.com/?b=a&a=b'
        );

        $middleware = new Oauth1Middleware($loop);
        $result = await($middleware->pre($request, $options), $loop);

        $this->assertNotSame($request, $result);

        $headers = $result->getHeaders();
        $this->assertTrue(isset($headers['Host']));
        $this->assertSame(
            [
                'example.com',
            ],
            $headers['Host']
        );
    }
}
