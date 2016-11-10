<?php
/**
 * Created by IntelliJ IDEA.
 * User: artur
 * Date: 11.10.16
 * Time: 14:05
 */

namespace Q3i\NawSso\Adapter;

/**
 * Class AbstractAdapter
 * @package Q3i\NawSso\Adapter
 */
abstract class AbstractAdapter
{

    /**
     * The configuration data of the target system
     * created during the environment bootstrap of
     * the target system
     * @var null
     */
    protected $targetSystemConfig = null;

    /**
     * Storage for some global variables created by the bootstrapping process
     * of the target system or by SSO Agent script
     * @var array
     */
    protected $globalData = array();

    /**
     * Storage for super globals as _GET, _SERVER etc.
     * which might get overwriten by the boostraiping process
     * of the target system
     * @var array
     */
    protected $superGlobals = array();

    /**
     * Root path of the target system
     * @var string
     */
    protected $rootPath = '';

    /**
     * Database handle setup to access
     * the database of the target system
     * @var $dbHandle mixed resource
     */
    protected $dbHandle;

    /**
     * @param $targetSystemRootPath
     */
    public function init($targetSystemRootPath) {
        $this->rootPath = $targetSystemRootPath;
        $this->superGlobals['_SERVER'] = $_SERVER;
        $this->superGlobals['_GET'] = $_GET;
        $this->superGlobals['_SESSION'] = $_SESSION;
        $this->superGlobals['_REQUEST'] = $_REQUEST;
    }

    /**
     * @param $dbHandle
     */
    public function setDatabaseHandle($dbHandle) {
        $this->dbHandle = $dbHandle;
    }

    /**
     * Set the configuration fetched from the target system
     * @param $targetSystemConfig
     */
    public function setTargetSystemConfig($targetSystemConfig) {
        $this->targetSystemConfig = $targetSystemConfig;
    }

    /**
     * @param array $globalData
     */
    public function saveGlobalData(array $globalData) {
        foreach ($globalData as $key=>$val) {
            $this->setVariable($key, $val);
        }
    }

    /**
     * @param $key
     * @param $val
     */
    public function setVariable($key, $val) {
        $this->globalData[$key] = $val;
    }

    /**
     * @param $key
     * @return mixed
     */
    public function getVariable($key) {
        return $this->globalData[$key];
    }

    /**
     * Sets a cookie of the given name with the specified data for the given length of time.
     * @param $name
     * @param $cookiedata
     * @param $cookietime
     */
    public function setCookie($name, $cookiedata, $cookietime)
    {
        $name_data = rawurlencode($this->targetSystemConfig['cookie_name'] . '_' . $name) . '=' . rawurlencode($cookiedata);
        $expire = gmdate('D, d-M-Y H:i:s \\G\\M\\T', $cookietime);
        $domain = (!$this->targetSystemConfig['cookie_domain'] || $this->targetSystemConfig['cookie_domain'] == 'localhost' || $this->targetSystemConfig['cookie_domain'] == '127.0.0.1') ? '' : '; domain=' . $this->targetSystemConfig['cookie_domain'];

        header('Set-Cookie: ' . $name_data . '; expires=' . $expire . '; path=' . $this->targetSystemConfig['cookie_path'] . $domain . ((!$this->targetSystemConfig['cookie_secure']) ? '' : '; secure') . '; HttpOnly', false);
    }

    /**
     * Initialize newly created user to a full featured
     * user of the target system
     * @param $newUserId
     * @param $usergroup
     */
    abstract public function initUser($newUserId, $usergroup);

    /**
     * process the userdata string and return an associative array
     * @param string $sso_userdata: the data from fe_users (pipe-separated)
     * @return array $sso_userdata: the userdata
     * @throws \AdapterException
     */
    abstract public function processIncomingUserdata($sso_userdata);

    /**
     * Check whether the user given in SSO data already exists
     * @param $sso_userdata
     * @return mixed
     */
    abstract public function checkLocalUser($sso_userdata);

    /**
     * Parse the group information given in SSO data
     * @param $sso_userdata
     * @param array $allowedUserGroups
     * @param array $groupMap
     * @return array
     */
    abstract public function parseIncomingGroupData($sso_userdata, array $allowedUserGroups, array $groupMap);

    /**
     * Start processing
     * @param $sso_userdata
     * @param $sso_groups
     * @return array
     * @throws \AdapterException
     */
    abstract public function process($sso_userdata, $sso_groups);

    /**
     * @param $newUsername
     * @param null $existingLocalUserId
     * @return string
     */
    abstract protected function ensureUsernameUnique($newUsername, $existingLocalUserId = null);

    /**
     * Action: Create new user
     * @param $sso_userdata
     * @param $sso_groups
     * @return array
     */
    abstract protected function actionCreate($sso_userdata, $sso_groups);

    /**
     * Action: Update existing user
     * @param $sso_userdata
     * @param $sso_groups
     * @param $localUserData
     * @return array
     */
    abstract protected function actionModify($sso_userdata, $sso_groups, $localUserData);

    /**
     * Action: Login existing user
     * @param $localUserData
     * @return array
     */
    abstract protected function actionLogon($localUserData);

}