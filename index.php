<?php

session_start(); 

// require_once __DIR__ . '/connection.php';
require_once __DIR__ . '/vendor/autoload.php';

use Bigcommerce\Api\Client as Bigcommerce;
use Firebase\JWT\JWT;
use Guzzle\Http\Client;
use Handlebars\Handlebars;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

define('WH_USER', 'triggmine');
define('WH_PASS', 'ZX2{qwHq@%_6/U\'K');

// Load from .env file
$dotenv = new Dotenv\Dotenv(__DIR__);
$dotenv->load();

$app = new Application();
$app['debug'] = true;


function logger ($log) {
	
	if (is_object($log) || is_array($log) || is_bool($log)) {
		ob_start();
		var_dump($log);
		$log = strip_tags(ob_get_clean());
	}
	
	$dir = './var/log/';
	file_put_contents($dir . 'log-' . date("y-m-d") . '.txt', "\r\n" . $log, FILE_APPEND);
}

function getBCtoken ($store_hash) {
	
	$redis = new Credis_Client('localhost');
	
	$store = $redis->get("stores/{$store_hash}/auth");
	$store = json_decode($store);
	$token = $store->access_token;
	
	return $token;
}



$app->get('/load', function (Request $request) use ($app) {

	$req = verifySignedRequest($request->get('signed_payload'));
	
	$data = $_SESSION["DATA"] = empty($req) ? $_SESSION["DATA"] : $req;
	
	if (empty($data)) {
		
		return 'Invalid signed_payload.';
	}
	
	$redis = new Credis_Client('localhost');
	$key = getUserKey($data['store_hash'], $data['user']['email']);
	$user = json_decode($redis->get($key), true);
	
	if (empty($user)) {
		
		return 'Invalid user.';
	}
	
	// return 'Welcome ' . json_encode($user);

	logger(json_encode($data));
	
	// $token = getBCtoken($data['store_hash']);
	// $connection = new connection('1ihy3srzlkhqzqokuj6rz43zaozmv94', $data['store_hash'], $token);
	// $store = $connection->get('/store');
	// logger(json_encode($store));
	
	// logger(json_encode($data['store_hash']));
	// $token = getBCtoken($data['store_hash']);
	// logger(json_encode($token));
	// 1ihy3srzlkhqzqokuj6rz43zaozmv94
	
	// $store = $redis->get("stores/{$data['store_hash']}/auth");
	// $store = json_decode($store);
	// $token = $store->access_token;
	
	
	// Generate the recently purchased products HTML
	$getHtmlAdminPanel = getHtmlAdminPanel($data['store_hash']);
	
	// Now respond with the generated HTML
	$headers = [];
	$response = new Response($getHtmlAdminPanel, 200, $headers);
	
	return $response;
});

$app->get('/auth/callback', function (Request $request) use ($app) {
	
	$redis = new Credis_Client('localhost');

	$payload = array(
		'client_id'		=> clientId(),
		'client_secret'	=> clientSecret(),
		'redirect_uri'	=> callbackUrl(),
		'grant_type'	=> 'authorization_code',
		'code'			=> $request->get('code'),
		'scope'			=> $request->get('scope'),
		'context'		=> $request->get('context')
	);

	$client = new Client(bcAuthService());
	
	$req = $client->post('/oauth2/token', array(), $payload, array(
		'exceptions' => false,
	));
	
	$resp = $req->send();
	
	if ($resp->getStatusCode() == 200) {
		
		$data = $resp->json();
		
		list($context, $storeHash) = explode('/', $data['context'], 2);
		$key = getUserKey($storeHash, $data['user']['email']);
		
		logger(json_encode($data));

		// Store the user data and auth data in our key-value store so we can fetch it later and make requests.
		$redis->set($key, json_encode($data['user'], true));
		$redis->set("stores/{$storeHash}/auth", json_encode($data));

		// return 'Hello ' . json_encode($data);
		
		// Generate the recently purchased products HTML
		$getHtmlAdminPanel = getHtmlAdminPanel($storeHash);
		
		// Now respond with the generated HTML
		$headers = [];
		$response = new Response($getHtmlAdminPanel, 200, $headers);
		
		return $response;
		
	} else {
		
		return 'Something went wrong... [' . $resp->getStatusCode() . '] ' . $resp->getBody();
	}

});

/**
 * GET /storefront/{storeHash}/customers/{jwtToken}/recently_purchased.html
 * Fetches the "Recently Purchased Products" HTML block and displays it in the frontend.
 */
$app->get('/storefront/{storeHash}/customers/{jwtToken}/recently_purchased.html', function ($storeHash, $jwtToken) use ($app) {
	
	$headers = ['Access-Control-Allow-Origin' => '*'];
	
	try {
		// First let's get the customer's ID from the token and confirm that they're who they say they are.
		$customerId = getCustomerIdFromToken($jwtToken);

		// Next let's initialize the BigCommerce API for the store requested so we can pull data from it.
		configureBCApi($storeHash);

		// Generate the recently purchased products HTML
		$recentlyPurchasedProductsHtml = getRecentlyPurchasedProductsHtml($storeHash, $customerId);

		// Now respond with the generated HTML
		$response = new Response($recentlyPurchasedProductsHtml, 200, $headers);
		
	} catch (Exception $e) {
		
		error_log("Error occurred while trying to get recently purchased items: {$e->getMessage()}");
		$response = new Response("", 500, $headers); // Empty string here to make sure we don't display any errors in the storefront.
	}

	return $response;
});


function checkAuthWebhook($request) {
	
	if ($request->headers->has('Authorization')) {
		
		$auth = $request->headers->get('Authorization');
		$authExpected = 'Basic ' . base64_encode(WH_USER . ':' . WH_PASS);
		
		// logger('ER: ' . $authExpected);
		// logger('AR: ' . $auth);
		
		if ($auth == $authExpected) {
			
			return true;			
		}
		else {
			
			return false;
		}
	}
	else {
		
		return false;
	}
}


/* Web-Hooks */
$app->post('/orders', function (Request $request) use ($app) {
	
	$body = $request->getContent();
	
	$headers = array(
		'Access-Control-Allow-Origin' => '*',
		'Content-Type' => 'application/json',
		'Accept' => 'application/json'
		);
		
	$status = 200;
	
	if (!checkAuthWebhook($request)) {
		
		$status = 401;
	}
	
	logger('order (' . $status . '): ' . $body);
	$response = new Response($body, $status, $headers);
	
	return $response;
});



/**
 * Gets the HTML block that displays the recently purchased products for a store.
 * @param string $storeHash
 * @param string $customerId
 * @return string HTML content to display in the storefront
 */
function getRecentlyPurchasedProductsHtml($storeHash, $customerId) {
	
	$redis = new Credis_Client('localhost');
	$cacheKey = "stores/{$storeHash}/customers/{$customerId}/recently_purchased_products.html";
	$cacheLifetime = 60 * 5; // Set a 5 minute cache lifetime for this HTML block.

	// First let's see if we can find he HTML block in the cache so we don't have to reach out to BigCommerce's servers.
	$cachedContent = json_decode($redis->get($cacheKey));
	
	if (!empty($cachedContent) && (int)$cachedContent->expiresAt > time()) { // Ensure the cache has not expired as well.
	
		return $cachedContent->content;
	}

	// Whelp looks like we couldn't find the HTML block in the cache, so we'll have to compile it ourselves.
	// First let's get all the customer's recently purchased products.
	$products = getRecentlyPurchasedProducts($customerId);

	// Render the template with the recently purchased products fetched from the BigCommerce server.
	$htmlContent =  (new Handlebars())->render(
		file_get_contents('templates/recently_purchased.html'),
		['products' => $products]
	);
	
	$htmlContent = str_ireplace('http', 'https', $htmlContent); // Ensures we have HTTPS links, which for some reason we don't always get.

	// Save the HTML content in the cache so we don't have to reach out to BigCommece's server too often.
	$redis->set($cacheKey, json_encode([ 'content' => $htmlContent, 'expiresAt' => time() + $cacheLifetime]));

	return $htmlContent;
}

/* Helper */

function getDateToday() {
	
	return (string) date("d.m.Y");
}

function getFirstDate() {
	
	return (string) "01.01." . date("Y");
}

function isSubmit() {
	
	$res = (isset($_GET['triggmine_settings_submit']) 
		&& $_GET['triggmine_settings_submit'] 
		&& $_GET['triggmine_settings_submit'] === "save") ? true : false;
		
	return (bool) $res;
}

function getSettings($el = '') {
	
	$el = strtolower($el);
	$res = trim(htmlspecialchars($_GET["triggmine_settings_$el"]));
	
	return (string) (strlen($res) > 0) ? $res : '';
}

function getSettingsEnable($el = '') {
	
	$el = strtolower($el);
	
	return (bool) ($_GET["triggmine_settings_$el"] == 1) ? true : false;
}

function getUrlShop() {
	
	return (string) $_SERVER['HTTP_HOST'];
}

function apiClient($storeHash, $data, $method, $url = null, $token = null) {
    
    $redis = new Credis_Client('localhost');
    $key = "stores/{$storeHash}/settings";
    
	$settings = $redis->get($key);
	$settings = json_decode($settings, true);

    $url   = $url ? $url : $settings[0]['API_URL'];
    $token = $token ? $token : $settings[0]['API_KEY'];

    if ($url == "")
    {
        $res = array(
            "status"    => 0,
            "body"      => ""
        );
    }
    else
    {
        $target = "https://" . $url . "/" . $method;

        $data_string = json_encode($data);
        
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $target);
        // curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data_string);           
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(                  
            'Content-Type: application/json',
            'ApiKey: ' . $token,
            'Content-Length: ' . strlen($data_string))
        );
        
        $res_json = curl_exec ($ch);
        
        $res = array(
            "status"    => curl_getinfo ($ch, CURLINFO_HTTP_CODE),
            "body"      => $res_json ? json_decode ($res_json, true) : curl_error ($ch)
        );
        
        curl_close ($ch);
    }
    
    return $res;
}


function getHtmlAdminPanel($storeHash)
{
	// logger(getSettingsEnable('enable_plugin'));
	// logger(getSettings('api_url'));
	// logger($_GET['triggmine_settings_is_on']);
	// logger($userId);
	
	$redis = new Credis_Client('localhost');
	$key = "stores/{$storeHash}/settings";
	$check_exist_key = $redis->exists($key);
	
	/**
	 * Event: Save Plaugin
	 */
	if(isSubmit()) {
		
		$settings = array(
			'ENABLE_PLUGIN'			=> getSettingsEnable('ENABLE_PLUGIN'),
			'API_URL'				=> getSettings('API_URL'),
			'API_KEY'				=> getSettings('API_KEY'),
			'ENABLE_ORDER'			=> getSettingsEnable('ENABLE_ORDER'),
			'ORDER_DATE_FROM'		=> getSettings('ORDER_DATE_FROM'),
			'ORDER_DATE_TO'			=> getSettings('ORDER_DATE_TO'),
			'ENABLE_CUSTOMERS'		=> getSettingsEnable('ENABLE_CUSTOMERS'),
			'CUSTOMERS_DATE_FROM'	=> getSettings('CUSTOMERS_DATE_FROM'),
			'CUSTOMERS_DATE_TO'		=> getSettings('CUSTOMERS_DATE_TO'),
			'ENABLE_PRODUCTS'		=> getSettingsEnable('ENABLE_PRODUCTS'),
			'UTM_SOURCE'			=> getUrlShop()
		);

		$redis->set($key, json_encode(array($settings)));
		
		
		// Next let's initialize the BigCommerce API for the store requested so we can pull data from it.
		configureBCApi ($storeHash);
		
		$dataSoft = SoftChek ($settings['ENABLE_PLUGIN']);
		logger(json_encode($dataSoft));
		$resSoft = onDiagnosticInformationUpdated($storeHash, $dataSoft);
		logger(json_encode($resSoft));
		
		
		
	}
	elseif($check_exist_key) {
		
		$res = $redis->get($key);
		$arr = json_decode($res, true);
		
		$settings = $arr[0];
	}
	else {
		$settings = Array(
			'ENABLE_PLUGIN'			=> false,
			'API_URL'				=> '',
			'API_KEY'				=> '',
			'ENABLE_ORDER'			=> false,
			'ORDER_DATE_FROM'		=> getFirstDate(),
			'ORDER_DATE_TO'			=> getDateToday(),
			'ENABLE_CUSTOMERS'		=> false,
			'CUSTOMERS_DATE_FROM'	=> getFirstDate(),
			'CUSTOMERS_DATE_TO'		=> getDateToday(),
			'ENABLE_PRODUCTS'		=> false,
			'UTM_SOURCE'			=> getUrlShop()
		);
	}

	$htmlContent =  (new Handlebars())->render(
		file_get_contents('templates/admin_panel.html'),
		['settings' => $settings]
	);
	
	$htmlContent = str_ireplace('http', 'https', $htmlContent); // Ensures we have HTTPS links, which for some reason we don't always get.
	
	// Save the HTML content in the cache so we don't have to reach out to BigCommece's server too often.
	// $redis->set($cacheKey, json_encode([ 'content' => $htmlContent, 'expiresAt' => time() + $cacheLifetime]));
	
	return $htmlContent;
}

/**
 * Look at each of the customer's orders, and each of their order products and then pull down each product resource
 * that was purchased.
 * @param string $customerId ID of the customer that we want to retrieve the recently purchased products list for.
 * @return array<Bigcommerce\Resources\Product> An array of products from the BigCommerce API
 */
function getRecentlyPurchasedProducts($customerId)
{
	$products = [];

	foreach(Bigcommerce::getOrders(['customer_id' => $customerId]) as $order) {
		foreach (Bigcommerce::getOrderProducts($order->id) as $orderProduct) {
			array_push($products, Bigcommerce::getProduct($orderProduct->product_id));
		}
	}

	return $products;
}
/**
 * Configure the static BigCommerce API client with the authorized app's auth token, the client ID from the environment
 * and the store's hash as provided.
 * @param string $storeHash Store hash to point the BigCommece API to for outgoing requests.
 */
function configureBCApi($storeHash)
{
	Bigcommerce::configure(array(
		'client_id'		=> clientId(),
		'auth_token'	=> getAuthToken($storeHash),
		'store_hash'	=> $storeHash
	));
}

/**
 * @param string $storeHash store's hash that we want the access token for
 * @return string the oauth Access (aka Auth) Token to use in API requests.
 */
function getAuthToken($storeHash)
{
	$redis = new Credis_Client('localhost');
	$authData = json_decode($redis->get("stores/{$storeHash}/auth"));
	return $authData->access_token;
}

/**
 * @param string $jwtToken 	customer's JWT token sent from the storefront.
 * @return string customer's ID decoded and verified
 */
function getCustomerIdFromToken($jwtToken)
{
	$signedData = JWT::decode($jwtToken, clientSecret(), array('HS256', 'HS384', 'HS512', 'RS256'));
	return $signedData->customer->id;
}

/**
 * This is used by the `GET /load` endpoint to load the app in the BigCommerce control panel
 * @param string $signedRequest Pull signed data to verify it.
 * @return array|null null if bad request, array of data otherwise
 */
function verifySignedRequest($signedRequest)
{
	list($encodedData, $encodedSignature) = explode('.', $signedRequest, 2);

	// decode the data
	$signature = base64_decode($encodedSignature);
	$jsonStr = base64_decode($encodedData);
	$data = json_decode($jsonStr, true);

	// confirm the signature
	$expectedSignature = hash_hmac('sha256', $jsonStr, clientSecret(), $raw = false);
	if (!hash_equals($expectedSignature, $signature)) {
		error_log('Bad signed request from BigCommerce!');
		return null;
	}
	return $data;
}

/**
 * @return string Get the app's client ID from the environment vars
 */
function clientId()
{
	$clientId = getenv('BC_CLIENT_ID');
	return $clientId ?: '';
}

/**
 * @return string Get the app's client secret from the environment vars
 */
function clientSecret()
{
	$clientSecret = getenv('BC_CLIENT_SECRET');
	return $clientSecret ?: '';
}

/**
 * @return string Get the callback URL from the environment vars
 */
function callbackUrl()
{
	$callbackUrl = getenv('BC_CALLBACK_URL');
	return $callbackUrl ?: '';
}

/**
 * @return string Get auth service URL from the environment vars
 */
function bcAuthService()
{
	$bcAuthService = getenv('BC_AUTH_SERVICE');
	return $bcAuthService ?: '';
}

/**
 * @return string Get сonsolidation of data into a key
 */
function getUserKey($storeHash, $email)
{
	return "triggmine:$storeHash:$email";
}


function SoftChek($status) {
	
	$dataStore = Bigcommerce::getStore();
	logger(json_encode($dataStore));
	
	$datetime = date('Y-m-d\TH:i:s');
	$status = $status ? 1 : 0;
	
    $data = array(
        'dateCreated'       => $datetime,
        'diagnosticType'    => "InstallPlugin",
        'description'       => "BigCommerce " . $dataStore->plan_name . "/" . $dataStore->plan_level . " Plugin " . "3.23.1",
        'status'            => $status
    );
        
	return $data;
}

function onDiagnosticInformationUpdated($storeHash, $data)
{
    return apiClient($storeHash, $data, 'control/api/plugin/onDiagnosticInformationUpdated');
}

$app->run();
