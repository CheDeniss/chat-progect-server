<?php
namespace App\Database;

use PDO;
use PDOException;

class connection {
    private static ?PDO $connection = null;

    public static function connect(): PDO {

        //print_r(PDO::getAvailableDrivers());


        if (self::$connection === null) {
            try {             
                $dsn = "sqlsrv:Server=(localdb)\\MSSQLLocalDB;Database=ChatDB";
                $username = ""; // Якщо потрібен логін
                $password = ""; // Якщо потрібен пароль

                // Створюємо підключення до бази даних
                self::$connection = new PDO($dsn, $username, $password, [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, // Виведення помилок
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, // Результати у вигляді асоціативного масиву
                ]);

                //print_r(self::$connection->getAttribute( PDO::ATTR_CLIENT_VERSION ));

            } catch (PDOException $e) {
                die("Помилка підключення до бази даних: " . $e->getMessage());
            }
        }

        return self::$connection;
    }
}
