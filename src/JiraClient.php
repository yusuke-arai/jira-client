<?php
/**
 * JiraClient.php
 */

namespace JiraClient;

/**
 * JIRA OAuth client.
 *
 * For the first time, you have to be authorized and issued an access token by the service.
 * The steps are:
 *  1. Get a request token via <code>getRequestToken()</code>.
 *  2. Access the authorize url (you can get via <code>getAuthorizeUrl()</code>).
 *     <code>oauth_verifier</code> will be given to callback url by the query string.
 *  3. Get an access token via <code>getAccessToken()</code>.
 *
 * Then you can use REST API functions with the access token.
 */
class JiraClient
{
    /**
     * @var string JIRA base URI. (e.g. 'https://example.atlassian.net')
     */
    private $jiraBaseUrl;

    /**
     * @const URI to get a request token.
     */
    const REQUEST_TOKEN_URI = '/plugins/servlet/oauth/request-token';

    /**
     * @const URI to authorize.
     */
    const AUTHORIZE_URI = '/plugins/servlet/oauth/authorize';

    /**
     * @const URI to get an access token.
     */
    const ACCESS_TOKEN_URI = '/plugins/servlet/oauth/access-token';


    /**
     * @const OAuth signature method.
     */
    const SIGNATURE_METHOD = 'RSA-SHA1';

    /**
     * @var string OAuth consumer key.
     */
    private $consumerKey;

    /**
     * @var string File path of OpenSSL private key.
     */
    private $privateKeyPath;

    /**
     * @var string OAuth nonce.
     */
    private $nonce;

    /**
     * @var string OAuth timestamp.
     */
    private $timestamp;

    /**
     * @var string OAuth access token (oauth_token).
     */
    private $oauthToken;

    /**
     * JiraClient constructor.
     * @param string $jiraBaseUrl JIRA base url. e.g. 'https://example.atlassian.net'.
     * @param string $consumerKey OAuth consumer key.
     * @param string $opensslPrivateKeyPath File path of OpenSSL private key (PEM).
     * @param string $oauth_token OAuth access token.
     */
    public function __construct(string $jiraBaseUrl, string $consumerKey, string $opensslPrivateKeyPath,
                                string $oauth_token = null)
    {
        $this->jiraBaseUrl = $jiraBaseUrl;
        $this->consumerKey = $consumerKey;
        $this->oauthToken = $oauth_token;
        $this->privateKeyPath = $opensslPrivateKeyPath;
        $this->nonce = self::getNonce();
        $this->timestamp = '' . time();
    }

    /**
     * Get request token.
     *
     * @param string $callbackUrl OAuth callback URL.
     * @return array
     * @throws JiraClientException
     */
    public function getRequestToken(string $callbackUrl)
    {
        $http_method = 'POST';
        $post_data = [
            'oauth_consumer_key' => $this->consumerKey,
            'oauth_callback' => $callbackUrl,
            'oauth_signature_method' => self::SIGNATURE_METHOD,
            'oauth_timestamp' => $this->timestamp,
            'oauth_nonce' => $this->nonce
        ];

        $requestUrl = $this->jiraBaseUrl . self::REQUEST_TOKEN_URI;
        $signature = $this->sign($http_method, $requestUrl, $post_data);
        $post_data['oauth_signature'] = $signature;
        $content = $this->buildQuery($post_data);
        $opts = [
            'http' => [
                'method' => $http_method,
                'header' => "Content-type: application/x-www-form-urlencoded\r\n" .
                    "Content-length: " . strlen($content),
                'content' => $content,
                'ignore_errors' => true
            ]
        ];
        $response = file_get_contents($requestUrl, false, stream_context_create($opts));
        parse_str($response, $result);

        if (isset($result['oauth_token'])) {
            return $result['oauth_token'];
        }
        throw new JiraClientException("Server response is '$response'.");
    }

    /**
     * Get url to authorize.
     * @param string $requestToken OAuth request token.
     * @return string URL
     */
    public function getAuthorizeUrl(string $requestToken): string
    {
        return $this->jiraBaseUrl . self::AUTHORIZE_URI . '?oauth_token=' . $requestToken;
    }

    /**
     * Process callback parameters of authorization.
     * Return verifier to get an access token.
     * @param array|string $params Parameters given by JIRA as a query string.
     * @return string Verifier to get an access token.
     * @throws JiraClientException
     */
    public function processCallback($params): string
    {
        if (is_string($params)) {
            $params = parse_str($params);
        }
        if (is_array($params) && is_string($params['oauth_verifier'])) {
            return $params['oauth_verifier'];
        }
        throw new JiraClientException('oauth_token is not given.');
    }

    /**
     * Get an access token via a request token and its verifier.
     * @param string $verifier OAuth access token verifier.
     * @return null|string OAuth access token. null if not given.
     * @throws JiraClientException
     */
    public function getAccessToken(string $verifier)
    {
        $http_method = 'POST';
        $data = [
            'oauth_consumer_key' => $this->consumerKey,
            'oauth_token' => $this->oauthToken,
            'oauth_signature_method' => self::SIGNATURE_METHOD,
            'oauth_timestamp' => $this->timestamp,
            'oauth_nonce' => $this->nonce,
            'oauth_verifier' => $verifier
        ];

        $url = $this->jiraBaseUrl . self::ACCESS_TOKEN_URI;
        $signature = $this->sign($http_method, $url, $data);
        $data['oauth_signature'] = $signature;
        $opts = [
            'http' => [
                'method' => $http_method,
                'ignore_errors' => true
            ]
        ];
        $response = file_get_contents($url . '?' . self::buildQuery($data), false, stream_context_create($opts));
        parse_str($response, $result);

        if (isset($result['oauth_token'])) {
            return $result['oauth_token'];
        }
        throw new JiraClientException("Server response is '$response'.");
    }

    /**
     * Create OAuth signature.
     * @param string $method
     * @param string $urlString
     * @param array $params Request parameters except signature. See OAuth 1.0 specification.
     * @return string Signature
     * @throws JiraClientException
     */
    private function sign(string $method, string $urlString, array $params)
    {
        $method = strtoupper($method);
        if ($method !== 'GET' and $method !== 'POST') {
            throw new JiraClientException('Invalid HTTP request method.');
        }

        $url = parse_url($urlString);
        if (!empty($url['query'])) {
            parse_str($url['query'], $query);
            $params = array_merge($params, $query);
        }

        ksort($params);

        $signature_base = $method . '&' .
            rawurlencode($url['scheme'] . '://' . $url['host'] . $url['path']) . '&' .
            rawurlencode($this->buildQuery($params));

        openssl_sign($signature_base, $signature,
            openssl_pkey_get_private('file://' . $this->privateKeyPath), OPENSSL_ALGO_SHA1);
        return base64_encode($signature);
    }

    /**
     * Get issues via JQL.
     * @param string $jql
     * @param int $maxResults Limit of number of results.
     * @return array Issues
     */
    public function getIssues(string $jql, int $maxResults = 100): array
    {
        $http_method = 'GET';
        $data = [
            'oauth_consumer_key' => $this->consumerKey,
            'oauth_token' => $this->oauthToken,
            'oauth_signature_method' => self::SIGNATURE_METHOD,
            'oauth_timestamp' => $this->timestamp,
            'oauth_nonce' => $this->nonce,
            'jql' => $jql,
            'maxResults' => $maxResults
        ];

        $url = $this->jiraBaseUrl . '/rest/api/2/search';
        $signature = $this->sign($http_method, $url, $data);
        $data['oauth_signature'] = $signature;
        $opts = [
            'http' => [
                'method' => $http_method,
                'ignore_errors' => true
            ]
        ];
        $result = file_get_contents($url . '?' . self::buildQuery($data), false, stream_context_create($opts));

        return json_decode($result, true);
    }

    /**
     * Format post data to of HTML form.
     * e.g. param1=data1&param2=data2&...
     * @param $data array
     * @return string
     */
    private static function buildQuery($data)
    {
        return http_build_query($data, null, '&', PHP_QUERY_RFC3986);
    }

    /**
     * Get a new nonce string
     * @return string Nonce string.
     */
    private static function getNonce()
    {
        return substr(base_convert(bin2hex(openssl_random_pseudo_bytes(64)), 16, 36), 0, 64);
    }
}
