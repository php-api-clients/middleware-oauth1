<?php declare(strict_types=1);

namespace ApiClients\Middleware\Oauth1;

use ApiClients\Tools\Psr7\Oauth1\Definition\AccessToken;
use ApiClients\Tools\Psr7\Oauth1\Definition\ConsumerKey;
use ApiClients\Tools\Psr7\Oauth1\Definition\ConsumerSecret;
use ApiClients\Tools\Psr7\Oauth1\Definition\TokenSecret;

final class Options
{
    const CONSUMER_KEY     = ConsumerKey::class;
    const CONSUMER_SECRET  = ConsumerSecret::class;
    const ACCESS_TOKEN     = AccessToken::class;
    const TOKEN_SECRET     = TokenSecret::class;
}
