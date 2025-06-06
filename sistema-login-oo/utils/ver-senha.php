<?php
$senha = "Seenha123";
$hash = password_hash($senha, PASSWORD_DEFAULT);

echo "Hash da senha: " . $hash;
?>