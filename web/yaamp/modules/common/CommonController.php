<?php
class CommonController extends CController
{
    public $memcache;
    public $t1;

    // read-only via getAdmin()
    private $admin = false;
    protected function getAdmin()
    {
        return $this->admin;
    }

    protected function elapsedTime()
    {
        $t2 = microtime(true);
        return ($t2 - $this->t1);
    }

    // True when the browser says the request was started by another web site
    // (a link, form, image or script on a foreign page), i.e. a possible CSRF.
    // Modern browsers send Sec-Fetch-Site, older ones Origin and/or Referer.
    // Requests without any of these headers (curl, scripts) are not cross-site.
    public function isCrossSiteRequest()
    {
        $site = arraySafeVal($_SERVER, 'HTTP_SEC_FETCH_SITE', '');
        if ($site == 'cross-site') return true;
        if ($site == 'same-origin' || $site == 'none') return false;

        $host = strtolower(arraySafeVal($_SERVER, 'HTTP_HOST', ''));
        foreach (array('HTTP_ORIGIN', 'HTTP_REFERER') as $header) {
            $value = arraySafeVal($_SERVER, $header, '');
            if (empty($value)) continue;
            if ($value == 'null') return true; // sandboxed/opaque origin
            $url = parse_url($value);
            if (!is_array($url) || empty($url['host'])) return true;
            $from = strtolower($url['host']) . (isset($url['port']) ? ':' . $url['port'] : '');
            return ($from != $host);
        }
        return false;
    }

    // Per-session token carried by the POST forms. The admin rights are only
    // granted to a POST which carries it (the headers checked above are not
    // sent by every client, in which case isCrossSiteRequest() cannot know).
    public function csrfToken()
    {
        $token = user()->getState('yaamp_csrf');
        if (!is_string($token) || strlen($token) != 32) {
            $token = bin2hex(random_bytes(16));
            user()->setState('yaamp_csrf', $token);
        }
        return $token;
    }

    public function csrfField()
    {
        return '<input type="hidden" name="csrf" value="' . $this->csrfToken() . '">';
    }

    public function hasValidCsrfToken()
    {
        $token = user()->getState('yaamp_csrf');
        $given = arraySafeVal($_POST, 'csrf', arraySafeVal($_SERVER, 'HTTP_X_CSRF_TOKEN', ''));
        return is_string($token) && $token !== '' && is_string($given) && hash_equals($token, $given);
    }

    protected function sendSecurityHeaders()
    {
        if (php_sapi_name() == 'cli' || headers_sent()) return;
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: SAMEORIGIN');
        header('Referrer-Policy: strict-origin-when-cross-origin');
    }

    protected function beforeAction($action)
    {
        //	debuglog("before action ".$action->getId());
        $this->memcache = new YaampMemcache;
        $this->t1 = microtime(true);

        $this->sendSecurityHeaders();

        // CSRF: refuse forms posted from foreign sites (the API is used by scripts)
        if (php_sapi_name() != 'cli' && $this->id != 'api' && app()->request->isPostRequest && $this->isCrossSiteRequest())
        {
            debuglog("cross-site POST refused {$this->id}/{$action->id} from ".arraySafeVal($_SERVER, 'REMOTE_ADDR'));
            throw new CHttpException(403, 'Cross-site request refused.');
        }

        if (user()
            ->getState('yaamp_admin'))
        {
            $this->admin = true;
            $client_ip = getClientIP();
            if (!isAdminIP($client_ip))
            {
                user()->setState('yaamp_admin', false);
                debuglog("admin attempt from $client_ip");
                $this->admin = false;
            }
            // CSRF: admin actions are plain links, never grant them to a
            // request initiated by another site (the session is kept).
            else if ($this->isCrossSiteRequest())
            {
                debuglog("admin rights ignored for cross-site request {$this->id}/{$action->id} from $client_ip");
                $this->admin = false;
            }
            // CSRF: the admin forms carry the session token
            else if (app()->request->isPostRequest && php_sapi_name() != 'cli' && !$this->hasValidCsrfToken())
            {
                debuglog("admin rights ignored for POST without token {$this->id}/{$action->id} from $client_ip");
                $this->admin = false;
            }
        }

        $algo = user()->getState('yaamp-algo');
        if (!$algo) user()->setState('yaamp-algo', YAAMP_DEFAULT_ALGO);

        return true;
    }

    protected function afterAction($action)
    {
        //	debuglog("after action ".$action->getId());
        $d1 = $this->elapsedTime();

        $url = "$this->id/{$this
            ->action->id}";
        $this
            ->memcache
            ->add_monitoring_function($url, $d1);
    }

    public function actionMaintenance()
    {
        $this->render('maintenance');
    }

    public function goback($count = - 1)
    {
        Javascript("window.history.go($count);");
        die;
    }

}
