<?php
use App\WebSocket\Chat;
use App\Database\connection;

use Ratchet\Http\HttpServer;
use Ratchet\Server\IoServer;
use Ratchet\WebSocket\WsServer;

require __DIR__ . '/vendor/autoload.php';

$db = connection::connect();

$server = IoServer::factory(
    new HttpServer(
        new WsServer(
            new Chat($db)
        )
    ),
    5237
);
$server->run();

