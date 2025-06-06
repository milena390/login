<?php
// Configuração do banco de dados
$host = 'localhost';
$dbname = 'sistema_login';
$username = 'root'; // Usuário padrão do MySQL
$password = '&tec77@info!'; // Senha padrão (altere conforme seu ambiente)

// Conexão com o banco de dados
$conn = new mysqli($host, $username, $password, $dbname);

// Verifica a conexão
if ($conn->connect_error) {
    die("Erro na conexão: " . $conn->connect_error);
}

// Função para validar o login
function validarLogin($email, $senha) {
    global $conn;
    
    // Prepara a consulta SQL para evitar SQL Injection
    $stmt = $conn->prepare("SELECT senha_hash FROM usuarios WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
        $usuario = $result->fetch_assoc();
        // Verifica a senha usando password_verify
        if (password_verify($senha, $usuario['senha_hash'])) {
            return true;
        }
    }
    return false;
}

// Função para sanitizar entradas
function sanitizarEntrada($dado) {
    return htmlspecialchars(strip_tags(trim($dado)));
}

// Exemplo de uso
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = sanitizarEntrada($_POST['email'] ?? '');
    $senha = sanitizarEntrada($_POST['senha'] ?? '');

    if (validarLogin($email, $senha)) {
        session_start();
        $_SESSION['logado'] = true;
        echo "Login bem-sucedido!";
    } else {
        echo "Email ou senha incorretos.";
    }
}
?>