<?php
session_start();

require_once __DIR__ . '/../models/UsuarioDAO.php';
require_once __DIR__ .  '/../utils/Sanitizacao.php';

// Sanitiza as entradas
$email = Sanitizacao::sanitizar($_POST['email']);
$senha = Sanitizacao::sanitizar($_POST['senha']);

// Valida o login
$usuarioDAO = new UsuarioDAO();
$usuario = $usuarioDAO->validarLogin($email, $senha);

if ($usuario) {
    $_SESSION['logado'] = true;
    $_SESSION['usuario_id'] = $usuario->getId();
    echo "Login bem-sucedido!";
} else {
    echo "Email ou senha incorretos.";
}
?>