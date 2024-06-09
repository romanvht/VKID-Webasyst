<?php

class vkidAuth extends waOAuth2Adapter
{
    const OAUTH_URL = "https://id.vk.com/auth";
    const API_URL = "https://api.vk.com/method/";
    const API_VERSION = '5.131';

    protected $check_state = true;

    /**
     * @return string
     * @see http://vk.com/dev/oauth_dialog
     */
    public function getRedirectUri()
    {
        $url = $this->getCallbackUrl();
        return self::OAUTH_URL."?uuid=".md5(uniqid(rand(), true))."&app_id=".$this->app_id."&response_type=silent_token&redirect_uri=".urlencode($url);
    }

    public function getControls()
    {
        return array(
            'app_id'     => 'ID приложения',
            'app_secret' => 'Секретный ключ',
            'app_service' => 'Сервисный токен',
        );
    }

    public function auth()
    {
        // check code
        $code = $this->getCode();
        if (!$code) {
            $url = $this->getRedirectUri();
            if ($this->check_state) {
                $state = md5(uniqid(rand(), true));
                wa()->getStorage()->set('auth_state', $state);
                $url .= '&redirect_state='.$state;
            }
            // redirect to provider auth page
            wa()->getResponse()->redirect($url);
        }

        if ($this->check_state) {
            $state = waRequest::request('state');
            $auth_state = wa()->getStorage()->get('auth_state');
            if (!$state || !$auth_state || $state !== wa()->getStorage()->get('auth_state')) {
                // @todo: error
                return array();
            }
        }

        // close session
        wa()->getStorage()->close();
        // get token
        if ($token = $this->getAccessToken($code)) {
            // get user info
            return $this->getUserData($token);
        }
        return array();
    }

    public function getAccessToken($code)
    {
        $url = self::API_URL."auth.exchangeSilentAuthToken?v=".self::API_VERSION."&token=".$code['token']."&access_token=".ifempty($this->options['app_service'])."&uuid=".$code['uuid'];
        $response = $this->get($url, $status);

        if (!$response) {
            waLog::log($this->getId(). ':'. $status. ': '."Can't get access token from VK", 'auth.log');
            throw new waAuthException("Can't get access token from VK", $status ? $status : 500);
        }
        $response = json_decode($response, true);
        if (isset($response['error']) && !isset($response['access_token'])) {
            waLog::log($this->getId(). ':'. $status. ': '.$response['error']." (".$response['error_description'].')', 'auth.log');
            throw new waAuthException($response['error']." (".$response['error_description'].')', $status ? $status : 500);
        }
        return $response;
    }

    public function getUserData($tokenRaw)
    {
        $token = $tokenRaw['response'];

        $url = self::API_URL."users.get?fields=contacts,sex,bdate,photo_medium&access_token={$token['access_token']}&v=".self::API_VERSION;
        $response = $this->get($url, $status);
        if ($response && $response = json_decode($response, true)) {
            if (isset($response['error'])) {
                waLog::log($this->getId(). ':'. $status. ': Error '.$response['error']['error_code']." (".$response['error']['error_msg'].')', 'auth.log');
                throw new waAuthException($response['error']['error_msg'], $response['error']['error_code']);
            }

            $response = ifset($response['response'][0]);
            if ($response) {
                $data = array(
                    'source'                  => 'vkid',
                    'source_id'               => $response['id'],
                    'socialnetwork.vkontakte' => $response['id'],
                    'url'                     => 'https://vk.com/id'.$response['id'],
                    'name'                    => trim(ifset($response['first_name'], '')." ".ifset($response['last_name'], '')),
                    'firstname'               => ifset($response['first_name'], ''),
                    'lastname'                => ifset($response['last_name'], ''),
                    'photo_url'               => ifset($response['photo_medium'], '')
                );
                if (!empty($token['email'])) {
                    $data['email'] = $token['email'];
                }
                if (!empty($token['phone'])) {
                    $data['phone'] = $token['phone'];
                }
                if (!empty($response['sex'])) {
                    $data['sex'] = $response['sex'] == 2 ? 'm' : 'f';
                }
                if (!empty($response['bdate'])) {
                    $b = explode('.', $response['bdate']);
                    if (count($b) == 3) {
                        $data['birthday'] = $b[2].'-'.$b[1].'-'.$b[0];
                    }
                }
                return $data;
            }
        }
        waLog::log($this->getId(). ':'. $status. ': '."Can't get user info from VK API", 'auth.log');
        throw new waAuthException("Can't get user info from VK API", $status ? $status : 500);
    }

    public function getName()
    {
        return wa()->getLocale() == 'en_US' ? 'VK ID' : 'VK ID';
    }

    public function getCallbackUrl($absolute = true)
    {
        return wa()->getRootUrl($absolute, true).'oauth.php/'.$this->getId();
    }

    public function getCode()
    {
        $payload = waRequest::request('payload');
        $code = json_decode($payload, true);

        return $code;
    }
}
