<?php declare(strict_types=1);

namespace ApiClients\Tests\Middleware\Oauth1;

use ApiClients\Middleware\Oauth1\Oauth1Middleware;
use ApiClients\Middleware\Oauth1\Options;
use ApiClients\Tools\Psr7\Oauth1\Definition;
use ApiClients\Tools\TestUtilities\TestCase;
use GuzzleHttp\Psr7\Request;
use Prophecy\Argument;
use Psr\Http\Message\RequestInterface;
use React\EventLoop\Factory;
use function Clue\React\Block\await;
use function React\Promise\resolve;

class Oauth1MiddlewareTest extends TestCase
{
    public function providerIncompleteRequestOptions()
    {
        $options = [];

        yield [
            $options,
        ];

        $options[Oauth1Middleware::class] = [];

        yield [
            $options,
        ];

        foreach ([
            Options::CONSUMER_KEY,
            Options::CONSUMER_SECRET,
            Options::ACCESS_TOKEN,
            Options::TOKEN_SECRET,
        ] as $option) {

            $options[Oauth1Middleware::class][$option] = $option;

            yield [
                $options,
            ];

            if ($option === Options::TOKEN_SECRET) {
                break;
            }

            $options[Oauth1Middleware::class][$option] = new $option($option);

            yield [
                $options,
            ];
        }
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
                Options::CONSUMER_KEY => new Definition\ConsumerKey(''),
                Options::CONSUMER_SECRET => new Definition\ConsumerSecret(''),
                Options::ACCESS_TOKEN => new Definition\AccessToken(''),
                Options::TOKEN_SECRET => new Definition\TokenSecret(''),
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
