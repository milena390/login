Explicação Detalhada:
1. Classe Database:
Objetivo: Centralizar a lógica de conexão com o banco de dados.

Encapsulamento: As configurações (host, nome do banco, etc.) são privadas para evitar acesso externo direto.

2. Propriedades:
$host: Endereço do servidor (geralmente localhost em ambiente local). $db_name: Nome do banco de dados (sistema_login). $username e $password: Credenciais de acesso (usuário root com senha root é comum em ambientes de desenvolvimento). $conn: Armazena o objeto PDO após a conexão.

3. Método getConnection():
Reinicialização: $this->conn = null garante que não haja conexões antigas.

Bloco try: -> Cria uma conexão PDO usando a string de conexão (mysql:host=...;dbname=...). -> Define PDO::ERRMODE_EXCEPTION para que erros gerem exceções (facilita a depuração).

Bloco catch: -> Captura exceções do tipo PDOException (erros de conexão ou configuração). -> die() interrompe a execução e exibe a mensagem de erro (útil para desenvolvimento, mas evite em produção).

Retorno: Devolve a conexão PDO ativa para ser utilizada em consultas.

Boas Práticas:
Segurança: Usar PDO com prepared statements previne SQL Injection.

Tratamento de Erros: Exceções permitem identificar problemas rapidamente.

Reusabilidade: A classe pode ser instanciada em qualquer parte do sistema para obter a conexão.

O que é PDO?
Camada de Abstração de Banco de Dados:
-> O PDO permite interagir com diferentes bancos de dados (MySQL, PostgreSQL, SQLite, etc.) usando uma sintaxe única. Isso significa que, se você migrar de MySQL para outro banco no futuro, apenas a string de conexão precisará ser ajustada, e não todo o código de interação com o banco.

Orientado a Objetos: O PDO é uma classe nativa do PHP, e sua utilização segue o paradigma de orientação a objetos, tornando o código mais organizado e moderno.

Como o PDO é usado no código?
No código da classe Database, o PDO é utilizado para criar uma conexão segura com o MySQL. Vamos analisar as partes relevantes:

a. Criação da conexão:

$this->conn = new PDO(
    "mysql:host={$this->host};dbname={$this->db_name}",
    $this->username,
    $this->password
);
String de Conexão (mysql:host=...;dbname=...): Define o driver (mysql), o servidor (host) e o nome do banco (dbname). Exemplo: "mysql:host=localhost;dbname=sistema_login".

Credenciais : O usuário (root) e senha (root) são passados para autenticar no banco de dados.

b. Configuração de Erros:

$this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
Modo de Erro: Define que o PDO deve lançar exceções (PDOException) quando ocorrerem erros (como falhas na conexão ou queries inválidas). Isso facilita o tratamento de erros com try/catch, como no código:

try { // Conexão PDO } catch (PDOException $e) { die("Erro na conexão: " . $e->getMessage()); }

Vantagens do PDO no código:
a. Segurança: - Proteção contra SQL Injection: O PDO suporta prepared statements (consultas preparadas), que evitam ataques de injeção de SQL ao separar dados de comandos. Exemplo de uso (não mostrado no código original, mas possível com PDO):

$stmt = $conn->prepare("SELECT * FROM usuarios WHERE email = :email");
$stmt->execute(['email' => $email]);
b. Portabilidade: - Se o sistema migrar para outro banco (ex: PostgreSQL), apenas a string de conexão precisa mudar (ex: pgsql:host=...), sem alterar o restante do código.

c. Tratamento de Erros Consistente: O uso de exceções (PDOException) permite capturar erros de forma centralizada e amigável.
Comparação com outras extensões:
mysqli: Extensão específica para MySQL, com funções procedural e orientada a objetos. Porém, só funciona com MySQL. Desvantagem: Menos flexível que o PDO.

PDO : Trabalha com múltiplos bancos e oferece uma API consistente, além de recursos avançados como transações e consultas preparadas.