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
        $this->setAllUsersStatusOffline(); // Встановлення всіх користувачів в статус "offline" про всяк випадок
        
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
            $conn->token = $token; // Зберігаємо токен
            $this->setUserStatus($conn);          
            

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

        if ($data['action'] !== 'register' && 
            $data['action'] !== 'login' && 
            !$this->validateToken($from->token ?? 'login', false)) {
            echo $this->colorText("onMessage:: ", "red")."Мабуть термін токена закінчився....\n";
            $this->send($from, 'tokenInvalid', ['message' => 'Мабуть термін токена закінчився....'], 'error');
            $this->setUserStatus($from, 'offline');
            $from->userId = null;
            $from->userName = null;
            $from->token = null;

            return;
        }        

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
                    $this->handleLogout($from);
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
                case 'getUserData':
                    $this->handleSendAuthUserData($from);
                    break;
                case 'search':
                    $this->handleSearchMessages($from, $data['data']);
                    break;
                case 'getGroupMembers':
                    $this->handleGetGroupMembers($from, $data['data']);
                    break;
                default:
                    $this->send( $from, 'error', ['message' => 'Невідома дія.'], 'error');
                    break;
            }
        } else { // Якщо action не вказаний
            $this->send( $from, 'error', ['message' => 'Дія не вказана.'], 'error');
        }
    }

    public function onClose(ConnectionInterface $conn): void
    {
        $connId = $conn->resourceId;
        $this->cleanupConnection($conn); // Видалення з'єднання зі списку та встановлення статусу "offline"
        echo $this->colorText("onClose:: ", "red")."З'єднання {$connId} закрите\n";
    }

    public function onError(ConnectionInterface $conn, \Exception $e): void
    {
        echo $this->colorText("onClose:: ", "red")."Помилка: {$e->getMessage()}\n";
        $conn->close();
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
                $from->userId = $user['id'];
                $from->userName = $userName;
                $from->token = $newToken;
                $this->setUserStatus($from);
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
     */
    private function handleCatchMessageFromClient(ConnectionInterface $from, array $data): void
    {
        //var_dump($data);
        if (!isset($data['message'], $data['chatId'], $data['isGroup'])) {
            $this->send($from, 'message', ['message' => 'Некоректні дані'], 'error');
            return;
        }
        try {
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
            
           /////////////////////////////////////
            $newMessageToSend['senderName'] = $from->userName;  // Додаємо поле `senderName`
            $newMessageToSend['isMyMessage'] = '1'; //['isMyMessage'] = '1' - своє повідомлення
            $this->send($from, 'newMessage', $newMessageToSend); // Відправляємо собі 
            ////////////////////////////////////            
            
            if (!$isGroup) {        // Якщо це не груповий чат - ['isMyMessage'] = '0' - чуже повідомлення
            foreach ($this->clients as $client) {
                if ($client->userId === $chatId && $client !== $from) {
                    $newMessageToSend['isMyMessage'] = '0';
                    $this->send($client, "newMessage", $newMessageToSend); 
                }
            }
            }else {   // Для групи відправляємо всім, окрім відправника - ['isMyMessage'] = '0' - чуже повідомлення
                foreach ($this->clients as $client) {
                    if ($client->userId !== $from_ && $this->isUserInChatRoom($client->userId, $chatId)) {
                        $newMessageToSend['isMyMessage'] = '0';
                        $this->send($client, 'newMessage', $newMessageToSend);
                    }
                }
            }

        } catch (PDOException $e) {
            $this->send($from, 'message', ['message' => 'Помилка відправлення повідомлення: ' . $e->getMessage()], 'error');
        } catch (Exception $e) {
            echo $this->colorText("handleCatchMessageFromClient:: ", "red") .
                "Помилка відправлення повідомлення: {$e->getMessage()}\n";
            $this->send($from, 'message', ['message' => 'Невідома помилка: ' . $e->getMessage()], 'error');
        }
    }  

    /**
     * Обробка реєстрації нового користувача
     */
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
            $from->token = $token;

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

    /**
     * Обробка запиту на отримання користувачів
     */
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

    /**
     * Обробка видалення повідомлення з бази
     */
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

    /**
     * Обробка отримання створення нової групи
     */
    private function handleCreateGroup(ConnectionInterface $from, mixed $data): void
    {
        if (!isset($data['name'], $data['members'])) {
            $this->send($from, 'createGroup', ['message' => 'Некоректні дані'], 'error');
            return;
        }

        try {
            $name = $data['name'];
            $users = $data['members'];
            $users[] = $from->userId;
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

            $this->send($from, 'groupCreated', ['message' => 'Група створена']);
        }
        catch (PDOException $e) {
            $this->send($from, 'createGroup', ['message' => 'Помилка створення групи: ' . $e->getMessage()], 'error');
        }        
    }      

    /**
     * Відправлення даних авторизованого користувача
     */
    private function handleSendAuthUserData(ConnectionInterface $from): void
    {
        $userId = $from->userId;
        try{
            $query = "SELECT name, email FROM users WHERE id = ?";
            $stmt = $this->db->prepare($query);
            $stmt->execute([$userId]);
            $userData = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($userData) {
                $this->send($from, 'setUserData', $userData);
                echo $this->colorText("handleSendAuthUserData:: ", "blue")."Дані користувача відправлені\n";
            } else {
                $this->send($from, 'setUserData', ['error' => 'Користувача не знайдено']);
            }
        } catch (PDOException $e) {
            echo "Помилка відправлення даних користувача: " . $e->getMessage();
            $this->send($from, 'userData', ['error' => 'Помилка сервера']);
        }
    }

    /**
     * Обробка пошуку повідомлень
     */
    private function handleSearchMessages(ConnectionInterface $from, mixed $data): void    
    {        
        //var_dump($data);
        try {
            $searchText = $data['searchText'] === '' ? '%' : "%{$data['searchText']}%";

            if (!$searchText || !isset($data['chatId'], $data['isGroup'])) {
                $this->send($from, 'searchMessages', ['message' => 'Некоректні дані для пошуку'], 'error');
                return;
            }

            $currentUserId = $from->userId;
            $isGroup = $data['isGroup'] === '1';
            $chatId = $data['chatId'];

            if ($isGroup) {
                // Пошук у груповому чаті
                $query = 'SELECT m.*, 
                     u.name AS senderName,
                     CASE 
                         WHEN m.sender_id = ? THEN 1
                         ELSE 0
                     END AS isMyMessage 
              FROM messages m
              LEFT JOIN users u ON m.sender_id = u.id
              WHERE m.chat_room_id = ? AND m.message LIKE ?
              ORDER BY m.created_at';
                $params = [$currentUserId, $chatId, "%$searchText%"];
            } else {
                // Пошук у приватному чаті
                $query = 'SELECT m.*, u.name AS senderName,
                        CASE 
                            WHEN m.sender_id = ? THEN 1
                            ELSE 0
                        END AS isMyMessage 
                      FROM messages m
                      LEFT JOIN users u ON m.sender_id = u.id
                      WHERE ((m.sender_id = ? AND m.receiver_id = ?) 
                             OR (m.sender_id = ? AND m.receiver_id = ?))
                        AND m.message LIKE ?
                      ORDER BY m.created_at';
                $params = [$currentUserId, $currentUserId, $chatId, $chatId, $currentUserId, "%$searchText%"];
            }

            $stmt = $this->db->prepare($query);
            $stmt->execute($params);

            $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $this->send($from, 'setMessages', $messages);

        } catch (PDOException $e) {
            $this->send($from, 'searchMessages', ['message' => 'Помилка пошуку: ' . $e->getMessage()], 'error');
        }
    }

    /**
     * Обробка отримання учасників групи
     */
    private function handleGetGroupMembers(ConnectionInterface $from, mixed $data): void
    {
        if (!isset($data['chatId'])) {
            $this->send($from, 'getGroupMembers', ['message' => 'Некоректні дані'], 'error');
            return;
        }
        try {
            $chatId = $data['chatId'];
            $query = "SELECT u.id, u.name FROM chat_members cm JOIN users u ON cm.user_id = u.id WHERE cm.chat_room_id = ?";
            $stmt = $this->db->prepare($query);
            $stmt->execute([$chatId]);
            $members = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $this->send($from, 'setGroupMembers', $members);
        }
        catch (PDOException $e) {
            $this->send($from, 'getGroupMembers', ['message' => 'Помилка отримання учасників групи: ' . $e->getMessage()], 'error');
        }          
    }

    /**   
     * Обробка виходу користувача
     */
    private function handleLogout($from): void{
        $this->setUserStatus($from, 'offline');
        $from->userId = null;
        $from->userName = null;
        $from->token = null;
        $this->send($from, 'logout', ['message' => 'Вихід успішний']);
        
        echo $this->colorText("handleLogout:: ", "red")."З'єднання {$from->resourceId} - користувач вийшов.\n";
    }


    /*****************************************************************************************/

    /**
     * Генерація токена
     */
    private function generateToken(string $userId): string
    {
        $payload = [
            'sub' => $userId,                   // ID користувача
            'iat' => time(),                    // Час створення токену
            'exp' => time() + 10 * 60            // Час закінчення через 3 хвилини
        ];
        $alg = 'HS256';

        return JWT::encode($payload, JWT_SECRET_KEY, $alg);
    }

    /**
     * Валідація токена
     */
    private function validateToken(string $token, bool $isLogin = true): bool
    {
        //echo $this->colorText("validateToken:: ", "blue")."Токен: {$token}\n";
        if($token === 'login') {
            return true;
        }
        
        try {
            $decoded = JWT::decode($token, new Key(JWT_SECRET_KEY, 'HS256'));
            //var_dump($decoded);

            if ($decoded->exp < time()) {
                throw new \Exception('Токен прострочений');
            }

            if ($isLogin) {
                return $this->checkUserInDatabase($decoded->sub);
            }

        } catch (\Exception $e) {
            echo "Помилка токена: {$e->getMessage()}\n";
            
            return false;
        }
        
        return true;
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
     * Встановлення всіх користувачів в статус "offline" при старті сервера про всяк випадок
     */
    private function setAllUsersStatusOffline(): void
    {
        try{
            $query = "UPDATE users SET status = 'offline'";
            $stmt = $this->db->prepare($query);
            $stmt->execute();
        }
        catch(PDOException $e){
            echo "Помилка встановлення всіх користувачів в статус 'offline': " . $e->getMessage();
        }
    }

    /**
     * Отримання імені користувача по його ID
     */
    private function getConnectedUserName($userId): string
    {
        $smtp = $this->db->prepare('SELECT name FROM users WHERE id = ?');
        $smtp->execute([$userId]);
        return $smtp->fetchColumn();
    }

    /**
     * Декодування токена та отримання ID користувача
     */
    private function getUserIdFromToken($token)
    {
        $decoded = JWT::decode($token, new Key(JWT_SECRET_KEY, 'HS256'));
        return $decoded->sub;
    }
    
    /**
     * Колір для логування в консолі
     */
    private function colorText(string $text, string $color, bool $bright = false): string
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

    /**
     * Генерація UUID
     */
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
    
    /**
     * Перевірка наявності користувача в чаті
     */
    private function isUserInChatRoom($userId, $chatRoomId): bool
    {
        $query = "SELECT 1 FROM chat_members WHERE user_id = ? AND chat_room_id = ?";
        $stmt = $this->db->prepare($query);
        $stmt->execute([$userId, $chatRoomId]);
        return (bool)$stmt->fetchColumn();
    }

    /**
     * Встановлення статусу користувача
     */
    private function setUserStatus($conn, string $status = 'online'): void
    {
        $name = $conn->userName;
        $id = $conn->userId;

        try {
            $stmt = $this->db->prepare('UPDATE users SET status = :status WHERE id = :id');
            $stmt->execute([':status' => $status, ':id' => $id]);

            // Формуємо push-сповіщення
            $message = json_encode([
                'action' => 'userStatusChanged',
                'data' => [
                    'userId' => $id,
                    'status' => $status
                ]
            ]);

            // Надсилаємо сповіщення всім клієнтам
            foreach ($this->clients as $client) {
                if ($client !== $conn) { // Не надсилаємо самому собі
                    $client->send($message);
                }
            }

            if($status === 'online') {
                echo $this->colorText("setUserStatus:: ", "yellow").
                    "Користувач {$this->colorText($name, "white", true)} - {$this->colorText($id, "white", true)} online\n";
            }
            else{
                echo $this->colorText("setUserStatus:: ", "yellow").
                    "Користувач {$this->colorText($name, "white", true)} - {$this->colorText($id, "white", true)} offline\n";}

            if ($stmt->rowCount() === 0) {
                echo $this->colorText("setUserStatus:: ", "yellow")."Користувач із ID {$id} не знайдений.\n";
            }
        } catch (PDOException $e) {
            echo $this->colorText("setUserStatus:: ", "cyan")."Помилка встановлення статусу {$status} для користувача {$id}: {$e->getMessage()}\n";
        }
    }

    /**
     * Формування json-відповіді для клієнта та надсилання її
     */
    private function send(ConnectionInterface $client, string $action, $data = [], string $status = 'success'): void
    {
        $message = [
            'status' => $status,
            'action' => $action,
            'data' => $data,
        ];

        $client->send(json_encode($message));
    }

    /**
     * Дії перед закриттям з'єднання
     */
    private function cleanupConnection(ConnectionInterface $conn): void
    {
        if ($conn->userId && $conn->userName) {
            echo $this->colorText("onClose:: ", "red") .
                "Користувач {$this->colorText($conn->userName, 'white', true)} - {$this->colorText($conn->userId, 'white', true)} виходить.\n";
            $this->setUserStatus($conn, 'offline');
        }else{
            echo $this->colorText("onClose:: ", "white").
                "Неавторизований користувач від'єднався від сервера.\n";
        }
        
        $this->clients->detach($conn);       
    }  
}