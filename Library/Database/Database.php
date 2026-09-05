<?php
declare(strict_types=1);

namespace Library\Database;

use PDO;
use PDOException;
use PDOStatement;
use Library\Config\Config;

class Database extends PDO
{
    /**
     * Database constructor, connects to the database
     */
    function __construct()
    {
        $dsn = 'mysql:host=' . Config::DB_HOST . ';dbname=' . Config::DB_NAME;
        
        try {
            parent::__construct($dsn, Config::DB_USER, Config::DB_PASS, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ]);
        } catch (PDOException $e) {
            print 'Error: ' . $e->getMessage() . '<br/>';
            die();
        }
    }

    /**
     * Run a database query
     *
     * @param string $sql - the SQL query to run
     * @param ?array $args - bind parameters
     * @return ?PDOStatement
     */
    public function DoQuery(string $sql, array $args = []): ?PDOStatement
    {
        $stmt = $this->prepare($sql);
        $stmt->execute($args);

        if ($stmt === false) {
            return null;
        }
        
        return $stmt;
    }
}
