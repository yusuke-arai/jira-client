jira-client
==

OAuth client library for JIRA.

# Install

Install via composer.

`php composer.phar require zamec75/jira-client`

# Get an OAuth access token.

1. Get a request token via `getRequestToken()`.
```
$client = new JiraClient('https://example.atlassian.net',
                         'EXAMPLE_CONSUMER_KEY',
                         'path/to/private/key');
$requestToken = $client->getRequestToken('http://example.com/callback');
```

2. Access the authorize url (you can get via `getAuthorizeUrl()`).
   `oauth_verifier` will be given to callback url by the query string.
   At your callback url, you can get the verifier given by JIRA.
```
$verifier = $_GET['oauth_verifier'];
```

3. Get an access token via `getAccessToken()`.
```
$client = new JiraClient('https://example.atlassian.net',
                         'EXAMPLE_CONSUMER_KEY',
                         'path/to/private/key',
                         $requestToken);
$accessToken = $client->getAccessToken($verifier);
```