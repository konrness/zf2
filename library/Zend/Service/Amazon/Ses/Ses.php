<?php
/**
 * Zend Framework
 *
 * LICENSE
 *
 * This source file is subject to the new BSD license that is bundled
 * with this package in the file LICENSE.txt.
 * It is also available through the world-wide-web at this URL:
 * http://framework.zend.com/license/new-bsd
 * If you did not receive a copy of the license and are unable to
 * obtain it through the world-wide-web, please send an email
 * to license@zend.com so we can send you a copy immediately.
 *
 * @category   Zend
 * @package    Zend_Service_Amazon
 * @subpackage Sqs
 * @copyright  Copyright (c) 2005-2010 Zend Technologies USA Inc. (http://www.zend.com)
 * @license    http://framework.zend.com/license/new-bsd     New BSD License
 */

/**
 * @namespace
 */
namespace Zend\Service\Amazon\Ses;
use Zend\Service\Amazon,
    Zend\Service\Amazon\Ses\Exception,
    Zend\Crypt;

/**
 * Class for connecting to the Amazon Simple Email Service (SES)
 *
 * @uses       SimpleXMLElement
 * @uses       Zend_Crypt_Hmac
 * @uses       Zend_Service_Amazon_Abstract
 * @uses       \Zend\Service\Amazon\Ses\Exception
 * @category   Zend
 * @package    Zend_Service
 * @subpackage Amazon_Ses
 * @copyright  Copyright (c) 2005-2010 Zend Technologies USA Inc. (http://www.zend.com)
 * @license    http://framework.zend.com/license/new-bsd     New BSD License
 * @see        http://aws.amazon.com/ses/ Amazon Simple Email Service
 *
 * @todo Add support for multiple endpoints (see ses.class.php)
 * @todo All common errors throw a RuntimeException (set the code but also see if the error name or description is available)
 */
class Ses extends \Zend\Service\Amazon\AbstractAmazon
{
    /**
     * HTTP end point for the Amazon SES service
     */
    protected $_sesEndpoint = 'email.us-east-1.amazonaws.com';

    /**
     * The API version to use
     */
    protected $_sesApiVersion = '2010-12-01';

    /**
     * Signature Version
     */
    protected $_sesSignatureVersion = '2';

    /**
     * Signature Encoding Method
     */
    protected $_sesSignatureMethod = 'HmacSHA256';

    /**
     * Constructor
     *
     * @param string $accessKey
     * @param string $secretKey
     * @param string $region
     */
    public function __construct($accessKey = null, $secretKey = null)
    {
        parent::__construct($accessKey, $secretKey);
    }

    /**
     * Make a request to Amazon SES
     *
     * @param  string           $action SES action
     * @param  array            $params
     * @return SimpleXMLElement
     */
    private function _makeRequest($action, $params = array())
    {
        $params['Action'] = $action;
        $params = $this->addRequiredParameters($params);

        $client = $this->getHttpClient();

        $client->setUri('https://'.$this->_sesEndpoint);

        $retry_count = 0;

        do {
            $retry = false;

            $client->resetParameters();
            $client->setParameterGet($params);

            $response = $client->request('GET');

            $response_code = $response->getStatus();

            // Some 5xx errors are expected, so retry automatically
            if ($response_code >= 500 && $response_code < 600 && $retry_count <= 5) {
                $retry = true;
                $retry_count++;
                sleep($retry_count / 4 * $retry_count);
            }
        } while ($retry);

        unset($client);

        return new \SimpleXMLElement($response->getBody());
    }

    /**
     * Adds required authentication and version parameters to an array of
     * parameters
     *
     * The required parameters are:
     * - AWSAccessKeyId
     * - SignatureVersion
     * - Timestamp
     * - Version
     * - Signature
     * - SignatureMethod
     *
     * If a required parameter is already set in the <tt>$parameters</tt> array,
     * it is overwritten.
     *
     * @param  array  $parameters the array to which to add the required
     *                            parameters.
     * @return array
     */
    protected function addRequiredParameters(array $parameters)
    {
        $parameters['AWSAccessKeyId']   = $this->_getAccessKey();
        $parameters['SignatureVersion'] = $this->_sesSignatureVersion;
        $parameters['Timestamp']        = gmdate('Y-m-d\TH:i:s\Z', time()+10);
        $parameters['Version']          = $this->_sesApiVersion;
        $parameters['SignatureMethod']  = $this->_sesSignatureMethod;
        $parameters['Signature']        = $this->_signParameters($parameters);

        return $parameters;
    }

    /**
     * Computes the RFC 2104-compliant HMAC signature for request parameters
     *
     * This implements the Amazon Web Services signature, as per the following
     * specification:
     *
     * 1. Sort all request parameters (including <tt>SignatureVersion</tt> and
     *    excluding <tt>Signature</tt>, the value of which is being created),
     *    ignoring case.
     *
     * 2. Iterate over the sorted list and append the parameter name (in its
     *    original case) and then its value. Do not URL-encode the parameter
     *    values before constructing this string. Do not use any separator
     *    characters when appending strings.
     *
     * @param  array  $parameters the parameters for which to get the signature.
     *
     * @return string the signed data.
     */
    protected function _signParameters(array $paramaters)
    {
        $data = "GET\n";
        $data .= $this->_sesEndpoint . "\n";
        
        uksort($paramaters, 'strcmp');
        unset($paramaters['Signature']);

        $arrData = array();
        foreach($paramaters as $key => $value) {
            $arrData[] = $key . '=' . str_replace('%7E', '~', urlencode($value));
        }

        $data .= implode('&', $arrData);

        $hmac = Crypt\Hmac::compute($this->_getSecretKey(), 'SHA256', $data, Crypt\Hmac::BINARY);

        return base64_encode($hmac);
    }
}
