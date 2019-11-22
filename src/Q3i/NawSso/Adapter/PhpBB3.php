<?php

namespace Q3i\NawSso\Adapter;

use Q3i\NawSso\Exception\AdapterException;
use Q3i\NawSso\Exception\UsernameTakenException;

/**
 * Created by IntelliJ IDEA.
 * 
 *  (c) net&works GmbH, Hannover, Germany
 *  http://www.single-signon.com
 *  (c) Q3i GmbH, Düsseldorf, Germany
 *  http://www.q3i.de
 */
class PhpBB3 extends AbstractAdapter
{

    /**
     * @param int $newUserId
     * @param array $accessDefinition
     */
    protected function initUser($newUserId, array $accessDefinition)
    {

        $forumsToSet = $accessDefinition['forums'];
        foreach ($forumsToSet as $forumId) {
            $this->aclGrantUserForum($newUserId, $forumId, true);
        }

        $accessGroups = $accessDefinition['groups'];
        foreach ($accessGroups as $groupId) {
            $this->aclGrantUserGroup($newUserId, $groupId, true);
        }

    }

    /**
     * process the userdata string and return an associative array
     * @param string $sso_userdata: the data from fe_users (pipe-separated)
     * @return array $sso_userdata: the userdata
     * @throws AdapterException
     */
    function processIncomingUserdata($sso_userdata)
    {
        $data = array();
        $sso_userdata = explode("|", $sso_userdata);
        for ($i = 0; $i < count($sso_userdata); $i++) {
            $sso_userdata[$i] = explode("=", $sso_userdata[$i]);
            $data[array_shift($sso_userdata[$i])] = implode('=', $sso_userdata[$i]);
        }
        unset ($sso_userdata);
        $sso_userdata = $data;

        // check "name" column
        if (!$sso_userdata['name'])
            throw new AdapterException("Field >>name<< mustn't be empty. Please check your source user data.");

        // check "username" column
        if (!$sso_userdata['username'])
            throw new AdapterException("Field >>username<< mustn't be empty. Please check your source user data.");

        // check "email" column
        if (!$sso_userdata['email'])
            throw new AdapterException("Field >>email<< mustn't be empty. Please check your source user data.");

        // reformat $User_Name

        //* begin : exception for air cargo germany - here nickname will be taken instead of name */
        // if (!$sso_userdata['tx_q8ycockpit_nickname']) return array("Error"=>"Field >>tx_q8ycockpit_nickname<< mustn't be empty. Please check your source user data.");
        //$sso_userdata['name'] = $sso_userdata['tx_q8ycockpit_nickname'];
        /* end : exception for air cargo germany - here nickname will be taken instead of name */

        //$sso_userdata['name'] = substr(str_replace("\\'", "'", $sso_userdata['name']), 0, 25);
        //$sso_userdata['name'] = str_replace("'", "\\'", $sso_userdata['name']);
        //$sso_userdata['name'] = str_replace(" ", ".", $sso_userdata['name']);

        return $sso_userdata;
    }

    /**
     * Check local user if present:
     * 1) first match with field q3i_typo3_username
     * 2) fallback to field user_email
     * 3) no local user found if neither 1) or 2) applies
     * @param $sso_userdata
     * @return mixed
     * @throws AdapterException
     */
    function checkLocalUser($sso_userdata) {

        $remoteIdentifier = strtolower(trim($sso_userdata['username']));
        $email = strtolower(trim($sso_userdata['email']));

        // check for typ3-identifier match (case insensitive)
        $sql = "SELECT user_id, q3i_typo3_username, username, user_password, user_sig FROM " . USERS_TABLE . " 
            WHERE q3i_typo3_username COLLATE UTF8_GENERAL_CI = '{$remoteIdentifier}'";
        if ($result = $this->dbHandle->sql_query($sql)) {
            $rows = $this->dbHandle->sql_fetchrowset($result);
            if (count($rows) > 1) {
                throw new AdapterException("Multiple users with the TYPO3 username (field:q3i_typo3_username) {$remoteIdentifier} available. Abort.");
            } else if (count($rows) == 1) {
                return $rows[0];
            }
        } else {
            throw new AdapterException("Error fetching user record.");
        }

        // no user with typo3-identifier match found
        // try fallback with email match (case insensitive)
        $sql = "SELECT user_id, q3i_typo3_username, username, user_password, user_sig FROM " . USERS_TABLE . " 
            WHERE user_email COLLATE UTF8_GENERAL_CI = '{$email}'";
        if ($result = $this->dbHandle->sql_query($sql)) {
            $rows = $this->dbHandle->sql_fetchrowset($result);
            if (count($rows) > 1) {
                throw new AdapterException("Multiple users with the email (field:user_email) {$email} available. Abort.");
            } else if (count($rows) == 1) {
                return $rows[0];
            }
        } else {
            throw new AdapterException("Error fetching user record.");
        }

    }

    /**
     * @param $sso_userdata
     * @param array $allowedUserGroups
     * @param array $groupMap
     * @return array
     * @throws AdapterException
     */
    function parseIncomingGroupData($sso_userdata, array $allowedUserGroups, array $groupMap) {

        // parse the submitted groups where the user is a member
        $sso_groups = explode(',',$sso_userdata['usergroup']);

        // build array with allowed group names
        $allowedGroupNames = Array();
        foreach ($allowedUserGroups as $key => $groupName) {
          if ($groupName) $allowedGroupNames[$key] = trim(strtolower($groupName));
        }

        // check if user belongs to one of allowed groups, if not - no access
        $intersec = Array('forums'=>array(),'groups'=>array());
        foreach ($sso_groups as $key => $userGroup) {
            $normalGroupName = trim(strtolower($userGroup));
           if (in_array($normalGroupName, $allowedGroupNames)) {
              if (array_key_exists($normalGroupName,$groupMap)) {
                 $mappingData = $groupMap[$normalGroupName];
                 $intersec['forums'] = array_unique(array_merge($intersec['forums'], explode(',', $mappingData['forums'])));
                 $intersec['groups'] = array_unique(array_merge($intersec['groups'], explode(',', $mappingData['groups'])));
              }
           }
        }

        if (!is_array($intersec) || count($intersec) == 0) {
           // group name not allowed for imported users
           throw new AdapterException("not allowed group membership");
        } else {
            $accessDefinition = $intersec;
        }

        return $accessDefinition;

    }

    /**
     * @param array $sso_userdata
     * @param array $accessDefinition
     * @return array
     * @throws AdapterException
     */
    function process(array $sso_userdata, array $accessDefinition) {

        // check if the given $User_Name exists in the DB
        $localUserData = $this->checkLocalUser($sso_userdata);

        $sso_action = $this->getVariable('action');
        $sso_flags = $this->getVariable('flags');        
        
        if (is_array($sso_flags) && $sso_flags['create_modify'] > 0) {
            $sso_action = 'create_modify';
        }

        switch ($sso_action) {

            // action: create user / update userdata
            case 'create_modify':

                if (!$localUserData) {
                    // given $User_Name doesn't exist in DB -> create new account
                    $localUserData = $this->actionCreate($sso_userdata, $accessDefinition);
                } else {
                    // user already exists, update profile with data from TYPO3's fe_users
                    // data used from fe_users: email
                    $this->actionModify($sso_userdata, $accessDefinition, $localUserData);
                }

                return $this->actionLogon($localUserData);

                break;

            // perform logon for given $User_Name
            case 'logon':
                if (!$localUserData) {
                    //no valid user found; return error
                    throw new AdapterException("No account for this user");
                } else {
                    return $this->actionLogon($localUserData);
                }
                break;

            default:
                throw new AdapterException('Unknown action');
                
        }        
        
    }

    /**
     * @param $newUsername
     * @param null $existingLocalUserId
     * @return string
     */
    protected function ensureUsernameUnique($newUsername, $existingLocalUserId = null) {

        /**
         * @param $newUsername
         * @param $dbHandle
         * @param null $existingLocalUserId
         * @return bool
         */
        function isUsernameUnique($newUsername, $dbHandle, $existingLocalUserId = null) {
            // check if username will be unique (case insensitive)
            $sql = "SELECT * FROM " . USERS_TABLE . " 
                WHERE username COLLATE UTF8_GENERAL_CI = '{$newUsername}'";
            if ($existingLocalUserId > 0) {
                $sql .= " AND NOT user_id = {$existingLocalUserId}";
            }
            $result = $dbHandle->sql_query($sql);
            $row_check = $dbHandle->sql_fetchrow($result);
            if ($row_check['user_id']) {
                return false;
            } else {
                return true;
            }
        }

        // ensure username to be unique
        $div = 0;
        $original_new_username = $newUsername;
        while (!isUsernameUnique($newUsername, $this->dbHandle, $existingLocalUserId)) {
            $div++;
            $newUsername = $original_new_username . " {$div}";
        }

        return $newUsername;

    }

    /**
     * Create/Modify user info signature
     * @param $sso_userdata
     * @param null|array $localUserData
     * @return string
     */
    protected function processUserInfoSignature($sso_userdata, array $localUserData = null) {

        $sig = '';
        if ($sso_userdata['company']) {
            $sig .= trim($sso_userdata['company']);
        }
        if ($localUserData['user_sig'] > '') {
            $localUserData['user_sig'] = str_replace($sig, '', $localUserData['user_sig']);
            $sig .= "\n" . trim($localUserData['user_sig']);
        }
        return $sig;

    }

    /**
     * Create new local user
     * @param $sso_userdata
     * @param $accessDefinition
     * @return mixed
     * @throws UsernameTakenException
     * @throws AdapterException
     */
    protected function actionCreate($sso_userdata, $accessDefinition) {

        $remoteIdentifier = strtolower(trim($sso_userdata['username']));
        $local_email = strtolower(trim($sso_userdata['email']));
        $local_username = $this->ensureUsernameUnique(trim($sso_userdata['name']));
        // username clean
        $local_username_clean = strtolower($local_username);
        $local_signature = $this->processUserInfoSignature($sso_userdata);

        // check if $remoteIdentifier will be unique (case insensitive)
        $sql = "SELECT user_id FROM " . USERS_TABLE . "
            WHERE q3i_typo3_username COLLATE UTF8_GENERAL_CI = '{$remoteIdentifier}'";
        $result = $this->dbHandle->sql_query($sql);
        $row_check = $this->dbHandle->sql_fetchrow($result);
        if ($row_check['user_id']) {
            // desired username is already taken
            throw new AdapterException("Remote identifier {$remoteIdentifier} is already taken. Please contact our support.");
        }

        // check if email will be unique (case insensitive)
        $sql = "SELECT user_id FROM " . USERS_TABLE . "
            WHERE user_email COLLATE UTF8_GENERAL_CI LIKE '{$local_email}'";
        $result = $this->dbHandle->sql_query($sql);
        $row_check = $this->dbHandle->sql_fetchrow($result);
        if ($row_check['user_id']) {
            // desired email address is already taken
            throw new AdapterException("E-Mail {$local_email} is already taken");
        }

        // determine the next free user_id;
        $sql = "SELECT MAX(user_id) AS total FROM " . USERS_TABLE;
        $result = $this->dbHandle->sql_query($sql);
        $row2 = $this->dbHandle->sql_fetchrow($result);
        $new_user_id = $row2['total'] + 1;

        // insert userdata into DB
        // data used from TYPO3's fe_users: email, country, website


        $sql = "SELECT group_id FROM " . GROUPS_TABLE . " WHERE group_name LIKE 'REGISTERED'";
        $result = $this->dbHandle->sql_query($sql);
        if (!$result) {
            throw new AdapterException("error fetching main user group");
        }

        $grpIdData = $this->dbHandle->sql_fetchrow();
        $group_id = $grpIdData['group_id'];
        $sql = "INSERT INTO " . USERS_TABLE 
            . " (
            user_id,
            username,
            username_clean,
            group_id,
            user_regdate,
            user_password,
            user_email,
            user_permissions,
            user_sig,
            user_lang,
            user_dateformat,
            user_style,
            user_lastvisit,
            user_lastmark,
            user_ip,
            user_colour,
            q3i_typo3_username
            )
               VALUES(
               '{$new_user_id}',
               '{$local_username}',
               '{$local_username_clean}',
               {$group_id},
               '" . time() . "',
               '%notallowed%',
               '{$local_email}',
               '',
               '{$local_signature}',
               'de',
               'D M d, Y g:i a',
               1,
               '" . time() . "',
               '" . time() . "',
               '" . $this->getVariable('ip') ."',
               '9E8DA7',
               '{$remoteIdentifier}'
               )";

        // var_dump($sql);die();
        if (!($result = $this->dbHandle->sql_query($sql)))
            throw new AdapterException("error creating user");

        // init ACL for the user
        $this->initUser($new_user_id, $accessDefinition);

        $sql = "SELECT user_id, username, user_password FROM " . USERS_TABLE . "
            WHERE username_clean = '" . $local_username_clean . "'";
        $result = $this->dbHandle->sql_query($sql);
        $localUserData = $this->dbHandle->sql_fetchrow($result);

        return $localUserData;

    }

    /**
     * Update existing local user record
     * @param $sso_userdata
     * @param $accessDefinition
     * @param $localUserData
     * @return array
     * @throws AdapterException
     */
    protected function actionModify($sso_userdata, $accessDefinition, $localUserData) {

        $remoteIdentifier = strtolower(trim($sso_userdata['username']));
        $local_email = strtolower(trim($sso_userdata['email']));
        $local_username = $this->ensureUsernameUnique(trim($sso_userdata['name']), $localUserData['user_id']);
        // username clean
        $local_username_clean = strtolower($local_username);
        $local_signature = $this->processUserInfoSignature($sso_userdata, $localUserData);

        // check if username was submitted and update if so
        if ($local_username && $localUserData['user_id']) {
            // update user name
            $sql = "UPDATE " . USERS_TABLE . " SET username='{$local_username}', username_clean='{$local_username_clean}' WHERE user_id='{$localUserData['user_id']}'";
            if (!($result = $this->dbHandle->sql_query($sql))) throw new AdapterException("error updating profile");
        }

        // check if $remoteIdentifier was submitted and update local reference if so
        if ($remoteIdentifier && !$localUserData['q3i_typo3_username']) {
            // check if remote identifier is available
            $sql = "SELECT user_id FROM " . USERS_TABLE . "
                WHERE q3i_typo3_username COLLATE UTF8_GENERAL_CI = '{$remoteIdentifier}' AND NOT user_id = {$localUserData['user_id']}";
            $result = $this->dbHandle->sql_query($sql);
            $row_check = $this->dbHandle->sql_fetchrow($result);
            if ($row_check['user_id']) {
                // desired username is already taken
                throw new AdapterException("Remote identifier {$remoteIdentifier} is already taken. Please contact our support.");
            }
            // update remote identifier
            $sql = "UPDATE " . USERS_TABLE . " SET q3i_typo3_username='{$remoteIdentifier}' where user_id='{$localUserData['user_id']}'";
            if (!($result = $this->dbHandle->sql_query($sql))) throw new AdapterException("error updating profile");
        }

        // check if email was submitted and update local if so
        if ($local_email) {
            // check if email is available
            $sql = "SELECT user_id FROM " . USERS_TABLE . "
                WHERE user_email COLLATE UTF8_GENERAL_CI = '{$local_email}' AND NOT user_id = {$localUserData['user_id']}";
            $result = $this->dbHandle->sql_query($sql);
            $row_check = $this->dbHandle->sql_fetchrow($result);
            if ($row_check['user_id']) {
                // desired username is already taken
                throw new AdapterException("E-Mail {$sso_userdata['email']} is already taken. Please contact our support.");
            }
            // update email
            $sql = "UPDATE " . USERS_TABLE . " SET user_email='{$local_email}' WHERE user_id='{$localUserData['user_id']}'";
            if (!($result = $this->dbHandle->sql_query($sql))) throw new AdapterException("error updating profile");
        }

        if ($local_signature) {
            // update signature
            $sql = "UPDATE " . USERS_TABLE . " SET user_sig='{$local_signature}' WHERE user_id='{$localUserData['user_id']}'";
            if (!($result = $this->dbHandle->sql_query($sql))) throw new AdapterException("error updating profile");
        }

        // update the usergroups:
        foreach ($accessDefinition['groups'] as $groupId) {
            // for each submitted TYPO3 group check if there's a group in phpBB
            $sql = "SELECT group_id FROM " . GROUPS_TABLE . " WHERE group_id = '{$groupId}'";
            $result = $this->dbHandle->sql_query($sql);
            if ($row = $this->dbHandle->sql_fetchrow($result)) {
                if (!$this->aclCheckUserGroup($localUserData['user_id'], $row['group_id'])) {
                    if (!$this->aclGrantUserGroup($localUserData['user_id'], $row['group_id'], true)) {
                        return array("Error" => "error updating group memberships");
                    }
                }
            } else {
                throw new AdapterException("Group ID {$groupId} not found locally");
            }
        }

        // update the user forum acl:
        foreach ($accessDefinition['forums'] as $forumId) {
            // for each submitted forum ID check if there's a forum in phpBB
            $sql = "SELECT forum_id FROM " . FORUMS_TABLE . " WHERE forum_id = '{$forumId}'";
            $result = $this->dbHandle->sql_query($sql);
            if ($row = $this->dbHandle->sql_fetchrow($result)) {
                if (!$this->aclCheckUserForum($localUserData['user_id'], $row['forum_id'])) {
                    if (!$this->aclGrantUserForum($localUserData['user_id'], $row['forum_id'], true)) {
                        return array("Error" => "error updating forum access");
                    }
                }
            } else {
                throw new AdapterException("Forum ID {$forumId} not found locally");
            }
        }

        // clear user permissions cache, PHPBB will recreate it based on the acl and group membership we set above
        $sql = "UPDATE " . USERS_TABLE . " SET user_permissions = '' WHERE user_id = {$localUserData['user_id']}";
        $this->dbHandle->sql_query($sql);

//        // remove user from all other groups than the TYPO3 ones
//        // first, get group_id and group_name from the DB
//        $sql = "SELECT " . GROUPS_TABLE . ".group_id, " . GROUPS_TABLE . ".group_name from " . USER_GROUP_TABLE .
//            " LEFT JOIN " . GROUPS_TABLE .
//            " ON " . USER_GROUP_TABLE . ".group_id = " . GROUPS_TABLE . ".group_id
//                where user_id = '{$localUserData['user_id']}' AND " . GROUPS_TABLE . ".group_type != 3";
//
//        $result = $this->dbHandle->sql_query($sql);
//        $is_member = $this->dbHandle->sql_fetchrowset($result);
//        if ($is_member) {
//            foreach ($is_member as $temp) {
//                // if the user is member to this group, but this group wasn't submitted by TYPO3 -> remove user
//                if ($temp['group_id'] > 0 && !in_array($temp['group_id'], $accessDefinition['groups'])) {
//                    $this->aclGrantUserGroup($localUserData['user_id'], $temp['group_id'], false);
//                }
//            }
//        }

    }

    /**
     * Create user session for the given local user
     * @param $localUserData
     * @return array
     */
    protected function actionLogon($localUserData) {

        //create the session
        define('IN_LOGIN', true);

        // Give us some basic information
        $userAgent = $_SERVER['HTTP_USER_AGENT'];
        $forwarderFor = $_SERVER['HTTP_USER_AGENT'];
        $httpHost = $_SERVER['$_SERVER'];

        // Give us some basic information
        $time_now = time();
        $update_session_page = 1;
        $browser = (!empty($userAgent)) ? htmlspecialchars((string)$userAgent) : '';
        $forwarded_for = (!empty($forwarderFor)) ? (string)$forwarderFor : '';
        $host = (!empty($httpHost)) ? (string)$httpHost : 'localhost';
        $page = 'index.php';

        $cookie_data['k'] = '';
        $cookie_data['u'] = $localUserData['user_id'];

        $sql = 'SELECT *
            FROM ' . USERS_TABLE . '
            WHERE user_id = ' . (int)$cookie_data['u'] . '
               AND user_type IN (' . USER_NORMAL . ', ' . USER_FOUNDER . ')';
        $result = $this->dbHandle->sql_query($sql);
        $data = $this->dbHandle->sql_fetchrow($result);
        $this->dbHandle->sql_freeresult($result);

        $data['session_last_visit'] = (isset($data['session_time']) && $data['session_time']) ? $data['session_time'] : (($data['user_lastvisit']) ? $data['user_lastvisit'] : time());

        // Force user id to be integer...
        $data['user_id'] = (int)$data['user_id'];

        $data['is_registered'] = ($data['user_id'] != ANONYMOUS && ($data['user_type'] == USER_NORMAL || $data['user_type'] == USER_FOUNDER)) ? true : false;
        $data['is_bot'] = false;


        // Create or update the session
        $sql_ary = array(
            'session_user_id' => (int)$data['user_id'],
            'session_start' => (int)$time_now,
            'session_last_visit' => (int)$data['session_last_visit'],
            'session_time' => (int)$time_now,
            'session_browser' => (string)substr($browser, 0, 149),
            'session_forwarded_for' => (string)$forwarded_for,
            'session_ip' => (string)$this->getVariable('ip'),
            'session_autologin' => 0,
            'session_admin' => 0,
            'session_viewonline' => 1,
        );

        $this->dbHandle->sql_return_on_error(true);

        $sql = 'DELETE
         FROM ' . SESSIONS_TABLE . '
         WHERE session_id = \'' . $this->dbHandle->sql_escape($data['session_id']) . '\'
            AND session_user_id = ' . ANONYMOUS;

        if (!defined('IN_ERROR_HANDLER') && (!$data['session_id'] || !$this->dbHandle->sql_query($sql) || !$this->dbHandle->sql_affectedrows())) {
            // Limit new sessions in 1 minute period (if required)
            if (empty($data['session_time']) && $this->targetSystemConfig['active_sessions']) {
                $sql = 'SELECT COUNT(session_id) AS sessions
               FROM ' . SESSIONS_TABLE . '
               WHERE session_time >= ' . ($time_now - 60);
                $result = $this->dbHandle->sql_query($sql);
                $localUserData = $this->dbHandle->sql_fetchrow($result);
                $this->dbHandle->sql_freeresult($result);

                if ((int)$localUserData['sessions'] > (int)$this->targetSystemConfig['active_sessions']) {
                    header('HTTP/1.1 503 Service Unavailable');
                    trigger_error('BOARD_UNAVAILABLE');
                }
            }
        }

        $data['session_id'] = md5(unique_id());

        $sql_ary['session_id'] = (string)$data['session_id'];
        $sql_ary['session_page'] = 'index.php';

        $sql = 'INSERT INTO ' . SESSIONS_TABLE . ' ' . $this->dbHandle->sql_build_array('INSERT', $sql_ary);
        $this->dbHandle->sql_query($sql);

        $this->dbHandle->sql_return_on_error(false);

        // refresh data
        $SID = '?sid=' . $data['session_id'];
        $_SID = $data['session_id'];
        $data = array_merge($data, $sql_ary);


        $cookie_expire = $time_now + (($this->targetSystemConfig['max_autologin_time']) ? 86400 * (int)$this->targetSystemConfig['max_autologin_time'] : 31536000);

        $this->setCookie('u', $cookie_data['u'], $cookie_expire);
        $this->setCookie('k', $cookie_data['k'], $cookie_expire);
        $this->setCookie('sid', $data['session_id'], $cookie_expire);

        unset($cookie_expire);

        $sql = 'SELECT COUNT(session_id) AS sessions
            FROM ' . SESSIONS_TABLE . '
            WHERE session_user_id = ' . (int)$data['user_id'] . '
            AND session_time >= ' . ($time_now - $this->targetSystemConfig['form_token_lifetime']);
        $result = $this->dbHandle->sql_query($sql);
        $localUserData = $this->dbHandle->sql_fetchrow($result);
        $this->dbHandle->sql_freeresult($result);

        if ((int)$localUserData['sessions'] <= 1 || empty($data['user_form_salt'])) {
            $data['user_form_salt'] = unique_id();
            // Update the form key
            $sql = 'UPDATE ' . USERS_TABLE . '
            SET user_form_salt = \'' . $this->dbHandle->sql_escape($data['user_form_salt']) . '\'
            WHERE user_id = ' . (int)$data['user_id'];
            $this->dbHandle->sql_query($sql);
        }


        $return_val[0] = array();
        $return_val += array("redirecturl" => $this->getVariable('sso_url'));
        // pass session data to the SSO-Agent

        if (strstr($return_val["redirecturl"], '?')) {
            $return_val["redirecturl"] .= "&sid=" . $data['session_id'];
        } else {
            $return_val["redirecturl"] .= "?sid=" . $data['session_id'];
        }

        return $return_val;

    }

    /**
     * Check users group membership
     * @param $userId
     * @param $groupId
     * @return bool
     */
    private function aclCheckUserGroup($userId, $groupId) {
        $sql = "SELECT * FROM " . USER_GROUP_TABLE . " 
                    WHERE group_id = '{$groupId}' AND user_id = '{$userId}'";
        $result = $this->dbHandle->sql_query($sql);
        $row = $this->dbHandle->sql_fetchrow($result);
        if (!$row) {
            return false;
        }
        return true;
    }

    /**
     * Add(remove) a user to group
     * @param $userId
     * @param $groupId
     * @param bool $allow
     * @return bool
     */
    private function aclGrantUserGroup($userId, $groupId, $allow=true) {
        $sql = null;
        if ($allow) {
            $sql = "INSERT INTO " . USER_GROUP_TABLE . " (group_id,user_id,user_pending) VALUES ('{$groupId}','{$userId}','0')";
        } else {
            $sql = "DELETE FROM " . USER_GROUP_TABLE . " WHERE user_id = '{$userId}' AND group_id = '{$groupId}'";
        }
        if (!($result = $this->dbHandle->sql_query($sql))) {
            return false;
        }
        return true;
    }

    /**
     * Check users group membership
     * @param $userId
     * @param $forumId
     * @return bool
     */
    private function aclCheckUserForum($userId, $forumId) {
        $sql = "SELECT * FROM phpbb_acl_users
                    WHERE user_id = '{$userId}' AND forum_id = '{$forumId}'";
        $result = $this->dbHandle->sql_query($sql);
        $row = $this->dbHandle->sql_fetchrow($result);
        if (!$row) {
            return false;
        }
        return true;
    }

    /**
     * Add(remove) a user to group
     * @param $userId
     * @param $forumId
     * @param bool $allow
     * @return bool
     */
    private function aclGrantUserForum($userId, $forumId, $allow=true) {
        $sql = null;
        if ($allow) {
            $sql = "INSERT INTO phpbb_acl_users (user_id, forum_id, auth_option_id, auth_role_id, auth_setting) 
                VALUES({$userId}, '$forumId', 0, 15, 0)";
        } else {
            $sql = "DELETE FROM phpbb_acl_users WHERE user_id = '{$userId}' AND forum_id = '{$forumId}'";
        }
        if (!($result = $this->dbHandle->sql_query($sql))) {
            return false;
        }
        return true;
    }

}
