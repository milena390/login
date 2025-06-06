<?php
// Função para validar o login
function validarLogin($email, $senha) {
    // Simula um banco de dados de usuários
    $usuarios = [
        [
            'email' => 'usuario@exemplo.com',
            'senha_hash' => password_hash('senha123', PASSWORD_DEFAULT)
        ]
    ];

    foreach ($usuarios as $usuario) {
        if ($usuario['email'] === $email && password_verify($senha, $usuario['senha_hash'])) {
            return true; // Login válido
        }
    }
    return false; // Login inválido
}

// Função para sanitizar entradas (evitar SQL Injection)
function sanitizarEntrada($dado) {
    return htmlspecialchars(strip_tags(trim($dado)));
}

// Exemplo de uso
$email = sanitizarEntrada($_POST['email'] ?? '');
$senha = sanitizarEntrada($_POST['senha'] ?? '');

if (validarLogin($email, $senha)) {
    session_start();
    $_SESSION['logado'] = true;
    echo "Login bem-sucedido!";
} else {
    echo "Email ou senha incorretos.";
}
?>