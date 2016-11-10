<?php
/*
* Signature-Based Single Sign-On Framework
* TPA Adapter for
* phpBB (http://www.phpBB.com )
*
*  Version            : 1.0.0
*  Last update        : 10.11.2016
*
*  (c) net&works GmbH, Hannover, Germany
*  http://www.single-signon.com
*  (c) Q3i GmbH, Düsseldorf, Germany
*  http://www.q3i.de
*/

require('vendor/autoload.php');

use Q3i\NawSso\Exception\AdapterExceptionInterface;
use Q3i\NawSso\Exception\AdapterException;

/**
 * return the protocol version
 * @return string
 */
function get_version()
{
    return "2.0";
}

/**
 * Function which is called after including this file in the SSO-Agent.
 *
 * @param $User_Name
 * @param $ip
 * @param $agent
 * @param $sso_url
 * @param string $sso_version
 * @param string $sso_action
 * @param string $sso_userdata
 * @return string return the session data
 *
 * Leave stubs if you dont need all four params.
 * @throws AdapterException
 * @internal param
 *    User_Name    string    Username the Session will be created for
 *    ip           string    Remoteaddress of the users system
 *    agent        string    Browser
 *    sso_url      string    Url where the user will be redirected after establishing a session for him
 *    sso_version  string    the protocol version of the calling agent
 *    sso_action   string    the action to perform. Right now this is either 'logon' or 'create_modify'
 *    sso_userdata string    the userdata submitted by the agent
 *
 */
function sso($User_Name, $ip, $agent, $sso_url, $sso_version = "", $sso_action = "", $sso_userdata = "")
{
    global $adapter;
    global $request;
    global $client_ip;
    global $exec;
    global $user, $auth, $cache;
    global $HTTP_SERVER_VARS;

    if (!$adapter instanceof \Q3i\NawSso\Adapter\AbstractAdapter) {
        throw new AdapterException('SSO adapter is not available in global context.');
    }

    $adapter->saveGlobalData(Array(
        'User_Name'     => $User_Name,
        'ip'            => $ip,
        'agent'         => $agent,
        'sso_url'       => $sso_url,
        'version'       => $sso_version,
        'action'        => $sso_action,
        'userdata'      => $sso_userdata,
        'request'       => $request,
        'client_ip'     => $client_ip,
        'exec'          => $exec,
        'user'          => $user,
        'auth'          => $auth,
        'cache'         => $cache
    ));
    //$adapter->setVariable('HTTP_SERVER_VARS', $HTTP_SERVER_VARS );

    try {

        // make sure adapter runs with a V1-agent
        //if ($sso_version == "") $sso_action="logon";

        // alternative: return error
        if ($sso_version == "") throw new AdapterException("sso version out of date");

        // split up the userdata string
        $sso_userdata = $adapter->processIncomingUserdata($sso_userdata);

        // parse the submitted groups where the user is a member
        $groupMap = Array(
            // keys in lower characters !!!
            'intranet' => array(
                'groups'=>'2',
                'forums'=>'2'
            ),
            'mitarbeiterintranet' => array(
                'groups'=>'16',
                'forums'=>'12'
            )
        );
        $allowedGroups = array('Intranet', 'Mitarbeiterintranet');
        $accessDefinition = $adapter->parseIncomingGroupData($sso_userdata, $allowedGroups, $groupMap);

        return $adapter->process($sso_userdata, $accessDefinition);

    } catch (AdapterExceptionInterface $ae) {
        return array("Error" => $ae->getMessage());
    } catch (\Exception $e) {
        return array("Error" => $e->getMessage());
    }

}

/**
 * Init SSO adapter and target system environment
 */

define('IN_PHPBB', true);

$adapter = new \Q3i\NawSso\Adapter\PhpBB3();
$adapter->init(dirname(__FILE__) . "/");

// q3i save some global data since all global variables will
// be overriden after common.php has been included
$adapter->saveGlobalData(Array(
    'tpa_id'    => $GLOBALS['tpa_id'],
    'thistime'  => $GLOBALS['thistime'],
    'userName'  => $GLOBALS['userName'],
    'expires'   => $GLOBALS['expires'],
    'sign'      => $GLOBALS['sign'],
    'version'   => $GLOBALS['version'],
    'action'    => $GLOBALS['action'],
    'flags'     => $GLOBALS['flags'],
    'userdata'  => $GLOBALS['userdata']
));


/**
 * BEGIN: start PhpBB3 environment
 * This must be done since many globals will be defined
 * during target systems bootstrap process
 */
$phpbb_root_path = dirname(__FILE__) . "/";
$phpEx = 'php';
include_once($phpbb_root_path . "common.php");
// enable super globals to be able to access
// such globals as $_GET, $_SERVER etc.
$request->enable_super_globals();
// END: start PhpBB3 environment

// set system config
$targetSystemConfig = &$config;
$adapter->setTargetSystemConfig($targetSystemConfig);

// set database handle
$adapter->setDatabaseHandle($GLOBALS['db']);
