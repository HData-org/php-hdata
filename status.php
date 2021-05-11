<?php

header('Content-Type: application/json');

require ('src/HData.php');

$host = "127.0.0.1";
$port = 8888;

$hdata = new HData($host, $port);

echo $hdata->getStatus();

$hdata->disconnect();