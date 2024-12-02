<?php
namespace App\WebSocket;

require_once 'config/key.php';

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use PDO;
use PDOException;
use Ratchet\MessageComponentInterface;
use Ratchet\ConnectionInterface;
use SplObjectStorage;

class Chat implements MessageComponentInterface {
    protected SplObjectStorage $clients;
    private PDO $db;

    public function __construct(PDO $db) {
        $this->clients = new SplObjectStorage; 
        $this->db = $db; // Підключення до бази
        echo "Сервер запущений\n";
    }

    public function onOpen(ConnectionInterface $conn): void
    {
        // Розбір параметрів запиту
        $queryString = $conn->httpRequest->getUri()->getQuery();
        parse_str($queryString, $params);

        // Перевірка токена (може бути відсутнім)
        $token = $params['token'] ?? null;

        if ($token && $this->validateToken($token)) {
            $conn->userId = $this->getUserIdFromToken($token); // Зберігаємо ідентифікатор користувача
            $conn->userName = $this->getConnectedUserName($conn->userId); // Зберігаємо ім'я користувача
            $this->setUserStatus($conn->userId); // Встановлюємо статус "online"
            
            echo $this->colorText("onOpen:: ", "green") . "Авторизоване з`єднання: користувач {$this->colorText($conn->userName, 'white', true)} - {$this->colorText($conn->userId, 'white', true)}\n";            
        } else {
            $conn->userId = null; // Неавторизований користувач
            echo $this->colorText("onOpen:: ", "green") . "Неавторизоване з'єднання\n";
        }

        // Додаємо з'єднання до клієнтів
        $this->clients->attach($conn);
        echo $this->colorText("onOpen:: ", "green"). "Нове з'єднання: ({$conn->resourceId})\n";
    }


    public function onMessage(ConnectionInterface $from, $msg): void
    {
        $data = json_decode($msg, true);

        if (isset($data['action'])) {
            switch ($data['action']) {
                case 'register':
                    $this->handleRegister($from, $data['data']);
                    break;
                case 'login':
                    $this->handleLogin($from, $data['data']);
                    break;
                case 'message':
                    $this->handleCatchMessageFromClient($from, $data['data']);
                    break;
                case 'getUsers':
                    $this->handleGetUsers($from);
                    break;
                case 'logout':
                    $this->setUserStatus($from->userId, 'offline');
                    $from->userId = null;
                    $from->userName = null;
                    break;
                case 'getMessages':
                    $this->handleLoadMessagesIntoChatList($from, $data['data']);
                    break;
                case 'delMessage':
                    $this->handleDeleteMessageFromBase($from, $data['data']);
                    break;
                case 'createGroup':
                    $this->handleCreateGroup($from, $data['data']);
                    break;                    
                default:
                    $from->send(json_encode(['status' => 'error', 'message' => 'Невідома дія']));
                    break;
            }
        } else {
            // Якщо в повідомленні немає 'action', це може бути некоректним запитом
            $from->send(json_encode(['status' => 'error', 'message' => 'Дія не вказана']));
        }
    }


    public function onClose(ConnectionInterface $conn): void
    {
        // Встановлюємо статус "offline" для користувача      
        echo $this->colorText("onClose:: ", "red").
            "Користувач {$this->colorText($conn->userName, 'white', true)} - 
                        {$this->colorText($conn->userId, 'white', true)} вийшов з системи\n";
        
        $this->setUserStatus($conn->userId, 'offline');       
        
        $this->clients->detach($conn);
        echo $this->colorText("onClose:: ", "red")."З'єднання {$conn->resourceId} закрите\n";
    }

    public function onError(ConnectionInterface $conn, \Exception $e): void
    {
        echo $this->colorText("onClose:: ", "red")."Помилка: {$e->getMessage()}\n";
        $conn->close();
    }
    
    /**
     * Генерація токена
     */
    
    public function generateToken(string $userId): string
    {
        $payload = [
            'sub' => $userId,                   // ID користувача
            'iat' => time(),                    // Час створення токену
            'exp' => time() + 3600              // Термін дії токену (1 година)
        ];
        $alg = 'HS256';

        return JWT::encode($payload, JWT_SECRET_KEY, $alg);
    }

    /**
     * Валідація токена
     */
    private function validateToken(string $token): bool {
        try {
            // Декодування токена
            $decoded = JWT::decode($token, new Key(JWT_SECRET_KEY, 'HS256'));
            //var_dump($decoded);
            
            // Перевірка, чи не закінчився строк дії
            if ($decoded->exp < time()) {
                throw new \Exception('Токен прострочений');
            }
            

            // Перевірка користувача в базі
            return $this->checkUserInDatabase($decoded->sub);
            
        } catch (\Exception $e) {
            echo "Помилка токена: {$e->getMessage()}\n";
            return false;
        }
    }

    /**
     * Перевірка існування користувача в базі
     */
    private function checkUserInDatabase($userId): bool {
        $stmt = $this->db->prepare('SELECT COUNT(*) FROM users WHERE id = :id');
        $stmt->bindParam(':id', $userId, PDO::PARAM_INT);
        $stmt->execute();
        $count = $stmt->fetchColumn();

        if ($count > 0) {
            echo $this->colorText("checkUserInDatabase:: ", "blue")."Користувач з ID {$userId} знайдений.\n";
            return true;
        }

        echo $this->colorText("checkUserInDatabase:: ", "blue")."Користувача з ID {$userId} не знайдено.\n";
        return false;
    }    
    /**
     * Обробка аввторизації
     */
    private function handleLogin(ConnectionInterface $from, array $data): void
    {
        if (!isset($data['userName'], $data['password'])) {
            $this->send($from, 'login', ['message' => 'Некоректні дані'], 'error');
            return;
        }

        $userName = $data['userName'];
        $password = $data['password'];

        try {
            $stmt = $this->db->prepare("SELECT id, password FROM users WHERE name = ?");
            $stmt->execute([$userName]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user && password_verify($password, $user['password'])) {
                // Пароль правильний, створюємо токен
                $newToken = $this->generateToken($user['id']);

                // Надсилаємо токен клієнту
                $this->send($from, 'login', [
                    'status' => 'success',
                    'token' => $newToken,
                    'message' => 'Успішний вхід до системи'
                ]);                
                
                // Встановлюємо статус "online" для користувача
                $this->setUserStatus($user['id']);
                $from->userId = $user['id'];
                $from->userName = $userName;
            } else {
                // Якщо користувача не знайдено або пароль неправильний
                $this->send($from, 'login', [
                    'status' => 'error',
                    'message' => 'Неправильний логін або пароль'
                ]);
            }
        } catch (PDOException $e) {
            $this->send(
                $from, 
                'login', 
                [
                    'message' => 'Помилка входу: ' . $e->getMessage()
                ],
                'error');
        }
    }    
    
    
    /**
     * Обробка надсилань повідомлень чату
     */
    private function handleLoadMessagesIntoChatList(ConnectionInterface $from, mixed $data): void
    {
        try {
            if (isset($data['chatId']) && $data['isGroup'] === '0') {
                // Індивідуальний чат
                $currentUserId = $from->userId;
                $withId = $data['chatId'];

                $stmt = $this->db->prepare(
                    'SELECT m.*, 
                        u.name AS senderName,
                        CASE 
                            WHEN m.sender_id = ? THEN 1
                            ELSE 0
                        END AS isMyMessage 
                 FROM messages m
                 LEFT JOIN users u ON m.sender_id = u.id
                 WHERE (m.sender_id = ? AND m.receiver_id = ?) 
                    OR (m.sender_id = ? AND m.receiver_id = ?)
                 ORDER BY m.created_at'
                );
                $stmt->execute([$currentUserId, $currentUserId, $withId, $withId, $currentUserId]);
                $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);

                $count = count($messages);
                echo $this->colorText("handleGetMessages:: ", "yellow") . "Відправлено {$count} повідомлень\n";

                $this->send($from, 'setMessages', $messages);

            } elseif (isset($data['chatId']) && $data['isGroup'] === '1') {
                // Груповий чат
                $chatId = $data['chatId'];
                $currentUserId = $from->userId;

                $stmt = $this->db->prepare(
                    'SELECT m.*, 
                        u.name AS senderName,
                        CASE 
                            WHEN m.sender_id = ? THEN 1
                            ELSE 0
                        END AS isMyMessage 
                 FROM messages m
                 LEFT JOIN users u ON m.sender_id = u.id
                 WHERE m.chat_room_id = ? 
                 ORDER BY m.created_at'
                );
                $stmt->execute([$currentUserId, $chatId]);
                $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);

                $count = count($messages);
                echo $this->colorText("handleGetMessages:: ", "yellow") . "Відправлено {$count} повідомлень\n";

                $this->send($from, 'setMessages', $messages);

            } else {
                $this->send($from, 'getMessages', ['message' => 'Некоректні дані'], 'error');
            }
        } catch (PDOException $e) {
            echo $this->colorText("Помилка SQL: ", "red") . $e->getMessage() . "\n";
            $this->send($from, 'getMessages', ['message' => 'Помилка отримання повідомлень: ' . $e->getMessage()], 'error');
        } catch (Exception $e) {
            echo $this->colorText("Невідома помилка: ", "red") . $e->getMessage() . "\n";
            $this->send($from, 'getMessages', ['message' => 'Невідома помилка: ' . $e->getMessage()], 'error');
        }
    }
    

    /**
     * Обробка повідомлення від клієнта
     *     
     */
    private function handleCatchMessageFromClient(ConnectionInterface $from, array $data): void
    {
        //var_dump($data);

        try {
            if (!isset($data['message'], $data['chatId'], $data['isGroup'])) {
                $this->send($from, 'message', ['message' => 'Некоректні дані'], 'error');
                return;
            }

            $message = $data['message'];
            $chatId = $data['chatId'];
            $isGroup = $data['isGroup'] === '1'; // Груповий чат чи ні
            $from_ = $from->userId;

            $query = "
            INSERT INTO messages (sender_id, receiver_id, message, chat_room_id, created_at)
            OUTPUT INSERTED.id, INSERTED.chat_room_id, INSERTED.sender_id, INSERTED.receiver_id, INSERTED.message, INSERTED.created_at
            VALUES (?, ?, ?, ?, GETDATE())
        ";

            if ($isGroup) {
                // Для групового чату `receiver_id` завжди `null`, `chat_room_id` — це ID чату
                $stmt = $this->db->prepare($query);
                $stmt->execute([$from_, null, $message, $chatId]);
            } else {
                // Для приватного чату `chat_room_id` завжди `null`, `receiver_id` — це ID іншого користувача
                $stmt = $this->db->prepare($query);
                $stmt->execute([$from_, $chatId, $message, null]);
            }

            $newMessageToSend = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // Додаємо поля `isMyMessage` та `senderName`
            $newMessageToSend['isMyMessage'] = '1'; // Повідомлення завжди від поточного користувача
            $newMessageToSend['senderName'] = $from->userName; 

            $this->send($from, 'newMessage', $newMessageToSend);

//            echo $this->colorText("handleCatchMessageFromClient:: ", "yellow") .
//                "Повідомлення від користувача {$from_} до " . ($isGroup ? "чату {$chatId}" : "користувача {$chatId}") . " повернуто\n";

        } catch (PDOException $e) {
            $this->send($from, 'message', ['message' => 'Помилка відправлення повідомлення: ' . $e->getMessage()], 'error');
        } catch (Exception $e) {
            echo $this->colorText("handleCatchMessageFromClient:: ", "red") .
                "Помилка відправлення повідомлення: {$e->getMessage()}\n";
            $this->send($from, 'message', ['message' => 'Невідома помилка: ' . $e->getMessage()], 'error');
        }
    }


    private function setUserStatus($id, string $status = 'online'): void
    {
        $name = $this->getConnectedUserName($id);
        
        try {
            $stmt = $this->db->prepare('UPDATE users SET status = :status WHERE id = :id');
            $stmt->execute([':status' => $status, ':id' => $id]);
            
            if($status === 'online') {
                echo $this->colorText("setUserStatus:: ", "yellow").
                    "Користувач {$this->colorText($name, 'white', true)} - {$this->colorText($id, 'white', true)} online\n";
            } else{
            echo $this->colorText("setUserStatus:: ", "yellow").
                "Користувач {$this->colorText($name, 'white', true)} - {$this->colorText($id, 'white', true)} offline\n";}

            if ($stmt->rowCount() === 0) {
                echo $this->colorText("setUserStatus:: ", "yellow")."Користувач із ID {$id} не знайдений.\n";
            }
        } catch (PDOException $e) {
            echo $this->colorText("setUserStatus:: ", "cyan")."Помилка встановлення статусу {$status} для користувача {$id}: {$e->getMessage()}\n";
        }
    }

    private function handleRegister(ConnectionInterface $from, array $data): void
    {
        // Перевірка наявності необхідних даних
        if (!isset($data['userName'], $data['password'], $data['eMail'])) {
            $from->send(json_encode(['status' => 'error', 'message' => 'Некоректні дані']));
            return;
        }

        $userName = $data['userName'];
        $password = password_hash($data['password'], PASSWORD_DEFAULT);
        $eMail = $data['eMail'];
        $id = $this->generateUUID();
        
        try {
            // Додавання нового користувача в базу даних
            $stmt = $this->db->prepare("INSERT INTO users (id, name, password, email, status) VALUES (?, ?, ?, ?, ?)");
            $stmt->execute([$id, $userName, $password, $eMail, 'offline']);

            // Відправляємо токен і повідомлення про успішну реєстрацію
            $this->send($from, 'register', [
                'status' => 'success',
                'message' => 'Реєстрація успішна!',
            ]);
            
            // Створюємо токен для нового користувача
            $token = $this->generateToken($id);
            $from->userId = $id;
            $from->userName = $userName;

            // Відправляємо токен і повідомлення про успішну реєстрацію
            $this->send($from, 'login', [
                'status' => 'success',
                'message' => 'Ви автоматично авторизовані після реєстрації.',
                'token' => $token,
            ]);

            echo $this->colorText("handleRegister:: ", "purple")."Реєстрація нового користувача - {$this->colorText($userName, 'white, true')}\n";

        } catch (PDOException $e) {
            $this->send($from, 'register', ['message' => 'Помилка реєстрації: ' . $e->getMessage()], 'error');
        }       
    }
    
    private function getConnectedUserName($userId): string
    {
        $smtp = $this->db->prepare('SELECT name FROM users WHERE id = ?');
        $smtp->execute([$userId]);
        return $smtp->fetchColumn();
    }
  
    private function generateUUID(): string {
        return sprintf(
            '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }

    private function send(ConnectionInterface $client, string $action, $data = [], string $status = 'success'): void
    {
        $message = [
            'status' => $status,
            'action' => $action,
            'data' => $data,
        ];

        $client->send(json_encode($message));
    }

    private function getUserIdFromToken($token)
    {
        $decoded = JWT::decode($token, new Key(JWT_SECRET_KEY, 'HS256'));
        return $decoded->sub;
    }

    private function handleGetUsers(ConnectionInterface $from): void
    {
        $currentUserId = $from->userId;

        $query = "
WITH MessageUsers AS (
    SELECT 
        CASE 
            WHEN sender_id = ? THEN receiver_id
            ELSE sender_id 
        END AS user_id,
        created_at
    FROM 
        messages
    WHERE 
        sender_id = ? OR receiver_id = ?
),
LastMessages AS (
    SELECT 
        user_id,
        MAX(created_at) AS last_message_time
    FROM 
        MessageUsers
    GROUP BY 
        user_id
)
SELECT 
    u.id AS id, 
    u.name AS name, 
    COALESCE(m.message, '') AS lastMessage, 
    lm.last_message_time AS lastMessageTime,
    u.status,
    0 AS isGroup
FROM 
    users u
LEFT JOIN LastMessages lm ON u.id = lm.user_id
LEFT JOIN messages m ON
    (m.sender_id = u.id AND m.receiver_id = ? AND m.created_at = lm.last_message_time) OR
    (m.receiver_id = u.id AND m.sender_id = ? AND m.created_at = lm.last_message_time)
WHERE 
    u.id != ?

UNION ALL

SELECT 
    cr.id AS id,
    cr.name AS name,
    COALESCE(
        (SELECT TOP 1 m.message
         FROM messages m
         WHERE m.chat_room_id = cr.id
         ORDER BY m.created_at DESC), 
        ''
    ) AS lastMessage,
    MAX(m.created_at) AS lastMessageTime,
    NULL AS status,
    1 AS isGroup
FROM 
    chat_rooms cr
LEFT JOIN messages m ON m.chat_room_id = cr.id
WHERE 
    cr.id IN (
        SELECT chat_room_id 
        FROM chat_members 
        WHERE user_id = ?
    )
GROUP BY 
    cr.id, cr.name
ORDER BY 
    lastMessageTime DESC;
";

        try {
            $stmt = $this->db->prepare($query);
            $stmt->execute([$currentUserId, 
                            $currentUserId, 
                            $currentUserId, 
                            $currentUserId, 
                            $currentUserId, 
                            $currentUserId, 
                            $currentUserId
                            ]);
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
            //var_dump($users);
            $this->send($from, 'setUsers', $users);
        } catch (PDOException $e) {
            echo "Помилка отримання користувачів: " . $e->getMessage();
        }
    }

    function colorText(string $text, string $color, bool $bright = false): string
    {
        $baseColors = [
            'black' => '30',
            'red' => '31',
            'green' => '32',
            'yellow' => '33',
            'blue' => '34',
            'purple' => '35',
            'cyan' => '36',
            'white' => '37',
        ];

        $colorCode = $baseColors[$color] ?? '0';
        if ($bright) {
            $colorCode = (string)((int)$colorCode + 60);
        }

        return "\033[{$colorCode}m{$text}\033[0m";
    }

    private function handleDeleteMessageFromBase(ConnectionInterface $from, mixed $data): void
    {
        if (!isset($data['id'])) {
            $this->send($from, 'delMessage', ['message' => 'Некоректні дані'], 'error');
            return;
        }

        $messageId = $data['id'];
        $sender_id = $data['sender_id'];
        $receiver_id = $data['receiver_id'];

        $stmt = $this->db->prepare('DELETE FROM messages WHERE id = ? AND (sender_id = ? OR receiver_id = ?)');
        $stmt->execute([$messageId, $sender_id, $receiver_id]);

        if ($stmt->rowCount() > 0) {
            $this->send($from, 'delMessage', ['message' => 'Повідомлення видалено']);
            $this->send($from, "messageDeleted", $messageId);
        } else {
            $this->send($from, 'delMessage', ['message' => 'Помилка видалення повідомлення'], 'error');
        }
    }

    private function handleCreateGroup(ConnectionInterface $from, mixed $data): void
    {
        if (!isset($data['name'], $data['members'])) {
            $this->send($from, 'createGroup', ['message' => 'Некоректні дані'], 'error');
            return;
        }

        $name = $data['name'];
        $users = $data['members'];
        $users[] = $from->userId; // Додаємо ініціатора групи до учасників
        $chatRoomId = $this->generateUUID(); 

        // Вставка в таблицю chat_rooms
        $query = "INSERT INTO chat_rooms (id, name) VALUES (?, ?)";
        $stmt = $this->db->prepare($query);
        $stmt->execute([$chatRoomId, $name]);

        // Вставки в таблицю chat_members
        $query = "INSERT INTO chat_members (chat_room_id, user_id) VALUES ";
        $values = [];
        $params = [];
        foreach ($users as $userId) {
            $values[] = "(?, ?)";
            $params[] = $chatRoomId; 
            $params[] = $userId;    
        }
        $query .= implode(', ', $values); 
        $stmt = $this->db->prepare($query);
        $stmt->execute($params);

        $this->send($from, 'createGroup', ['message' => 'Група створена']);
    }


    public function updateUserStatus(ConnectionInterface $conn, string $status)
    {
        $userId = $conn->userId;

        // Оновлюємо статус у базі даних
        $query = "UPDATE users SET status = ?, last_active = GETDATE() WHERE id = ?";
        $stmt = $this->db->prepare($query);
        $stmt->execute([$status, $userId]);

        // Формуємо push-сповіщення
        $message = json_encode([
            'type' => 'userStatusChanged',
            'data' => [
                'userId' => $userId,
                'status' => $status
            ]
        ]);

        // Надсилаємо сповіщення всім клієнтам
        foreach ($this->clients as $client) {
            if ($client !== $conn) { // Не надсилаємо самому собі
                $client->send($message);
            }
        }

        echo "Статус користувача {$userId} оновлено на '{$status}'\n";
    }

}