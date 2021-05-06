<?php

function sendCmd($cmd, $host, $port) {
    if($host == null || $host == "");
        $host = "127.0.0.1";
    if($port == null || $port == "");
        $port = 8888;
    
    $timeout = 10; //in seconds
    
    $fp = fsockopen($host, $port, $errno, $errstr, $timeout);
    
    if (!$fp) {
        echo "{ \"error\": \"".$errno."\" }\n";
    } else {
        $out = $cmd."\n";
        fwrite($fp, $out);
        while (!feof($fp)) {
            echo fgets($fp, 128);
        }
        fclose($fp);
    }
}

sendCmd($_REQUEST['cmd'], $_REQUEST['host'], $_REQUEST['port']);

?>