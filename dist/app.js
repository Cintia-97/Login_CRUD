// app.ts
import express from 'express';
import { verifyAccount, createUser, authenticateUser, updateUser, deleteUser, saveResetToken, verifyResetToken, updatePassword, getUserByEmail } from './services/postgresService.js';
import validator from 'validator';
import { testConnection } from './services/postgresService.js';
import dotenv from "dotenv";
import session from 'express-session';
import { isAuthenticated } from './middlewares/authMiddleware.js';
//Rota esqueci a senha
import crypto from 'crypto';
import nodemailer from 'nodemailer';
//Conexão com e-mail
dotenv.config();
// Testar conexão ao iniciar
testConnection();
const app = express();
const port = process.env.PORT || 3000;
//Configuração da sessão
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false },
}));
//Para acessar a pasta public (que contem meu css)
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true })); // For form data
// Rota para exibir a tela de escolha entre Login e Criar Conta
app.get('/', async (req, res) => {
    res.send(`
    <head>
      <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
      <h2>Seja bem-vindo(a)</h2>
      <a href="/register">Create Account</a> | <a href="/login">Login</a>
    </body>
  `);
});
// Rota para exibir o formulário de criação de conta
app.get('/register', async (req, res) => {
    res.send(`
    <head>
      <link rel="stylesheet" href="/styles.css">
    </head>
    <body>  
      <h2>Create User</h2>
      <form action="/users" method="POST">
        <label>Name: <input type="text" name="name" required></label><br>
        <label>Email: <input type="email" name="email" required></label><br>
        <label>Birthdate: <input type="date" name="birthdate" required></label><br>
        <label>Password: <input type="password" name="password" required></label><br>
        <label>Confirm Password: <input type="password" name="confirmPassword" required></label><br>
        <button type="submit">Create</button>
      </form>
    </body>
  `);
});
//Rota de Login do usuário
app.get('/login', async (req, res) => {
    res.send(`
    <head>
      <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
      <h2>Login</h2>
      <form action="/auth" method="POST">
        <label>Email: <input type="email" name="email" required></label><br>
        <label>Password: <input type="password" name="password" required></label><br>
        <a href="/forgot-password">Esqueci a senha</a><br>
        <button type="submit">Login</button>
      </form>
      <a href="/">Back</a>
    </body>
  `);
});
//Para criar um novo usuário e chama a função de conexão com o banco de dados
app.post('/users', (async (req, res) => {
    const { name, email, birthdate, password, confirmPassword } = req.body;
    if (!name || !email || !birthdate || !password || !confirmPassword) {
        return res.status(400).send('All fields are required');
    }
    if (!validator.isEmail(email)) {
        return res.status(400).send('Formato inválido de e-mail');
    }
    if (password !== confirmPassword) {
        return res.status(400).send('As senhas não coincidem');
    }
    // Gerar um token de verificação
    const verificationToken = crypto.randomBytes(32).toString('hex');
    console.log("token gerado:", verificationToken);
    // Envia e-mail de verificação
    const verificationLink = `http://localhost:3000/validado?token=${verificationToken}`;
    // Configuração do envio de e-mail
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER, //  email
            pass: process.env.EMAIL_PASS //  senha de app
        }
    });
    const mailOptions = {
        from: process.env.EMAIL_USER, //  email
        to: email,
        subject: 'Validação da conta',
        text: `Clique no link para validar a sua conta:
      
      ${verificationLink}`
    };
    try {
        await transporter.sendMail(mailOptions);
        await createUser(name, email, birthdate, password, verificationToken);
        res.send(`
      <head>
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body>
        <label>Olá ${name}, seu usuário criado! Verifique seu e-mail para ativar a conta!</label>
      </body><br>
      <a href="/">Início</a><br>
    `);
    }
    catch (err) {
        if (err instanceof Error && err.message.includes("Email already registered")) {
            return res.status(400).send("Email already exists.");
        }
        res.status(500).send(err instanceof Error ? err.message : 'Unexpected error');
    }
}));
//Valida a criação da conta
app.get('/validado', (async (req, res) => {
    const { token: verificationToken, email } = req.query;
    console.log("Email recebido:", email); // Verifique se o email está sendo passado corretamente
    console.log("Token recebido:", verificationToken);
    if (!verificationToken) {
        return res.status(400).send("Token inválido. Sério, muito errado!!");
    }
    res.send(`
<head>
<head>
      <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
      <h2>Conta Validada com Sucesso</h2>
      <form action="/validado" method="POST">
        <input type="hidden" name="email" value="${email}">  
        <input type="hidden" name="token" value="${verificationToken}">
        <a href="/login">Login</a>
      </form>
    </body>
  `);
}));
//Solicita a validação no banco de dados
app.post('/validado', (async (req, res) => {
    const { email, token: verificationToken } = req.body;
    console.log("Email recebido:", email); // Verifique se o email está sendo passado corretamente
    console.log("Token recebido:", verificationToken);
    const isValid = await verifyResetToken(email, verificationToken);
    console.log("validação:", isValid);
    if (!isValid) {
        return res.status(400).send("Token inválido ou expirado.");
    }
    await verifyAccount(verificationToken, email);
    res.send("Conta validada, faça login! <a href='/login'>Fazer login</a>");
}));
//Formulário de reset de senha
app.get('/forgot-password', (async (req, res) => {
    res.send(`
    <head>
      <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
      <h2>Esqueceu a senha?</h2>
      <form action="/forgot-password" method="POST">
        <label>Email: <input type="email" name="email" required></label><br>
        <button type="submit">Login</button>
      </form>
      <a href="/">Voltar</a>
    </body>
  `);
}));
//Rota para gerar o token e validar o e-mail
app.post('/forgot-password', (async (req, res) => {
    const { email } = req.body;
    const user = await getUserByEmail(email);
    if (!user) {
        return res.status(400).send(`
      <head>
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body>
        <label>E-mail não encontrado. Vamos fazer uma conta?</label>
      </body>
      <a href="/login">Login</a>
      `);
    }
    // Gerar um token único
    const token = crypto.randomBytes(32).toString('hex');
    console.log("token gerado:", token);
    // Salvar o token no banco com validade (ex: 1 hora)
    await saveResetToken(email, token);
    // Criar link para redefinição
    const resetLink = `http://localhost:3000/reset-password?token=${token}&email=${email}`;
    // Configuração do envio de e-mail
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER, //  email
            pass: process.env.EMAIL_PASS //  senha de app
        }
    });
    const mailOptions = {
        from: process.env.EMAIL_USER, //  email
        to: email,
        subject: 'Recuperação de Senha',
        text: `Clique no link para redefinir sua senha:
    
    ${resetLink}`
    };
    try {
        await transporter.sendMail(mailOptions);
        res.send(`
      <head>
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body>
        <label>E-mail enviado com sucesso! Verifique sua caixa de entrada</label>
      </body>
      <a href="/">Início</a>
      `);
    }
    catch (error) {
        res.status(500).send("Erro ao enviar e-mail.");
    }
}));
//Formulário para redefinir a senha após o envio do token
app.get('/reset-password', (async (req, res) => {
    const { token, email } = req.query;
    if (!token || !email) {
        return res.status(400).send("Token inválido.");
    }
    res.send(`
    <head>
      <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
      <h2>Redefinir Senha</h2>
      <form action="/reset-password" method="POST">
        <input type="hidden" name="email" value="${email}">
        <input type="hidden" name="token" value="${token}">
        <label>Nova Senha: <input type="password" name="password" required></label><br>
        <label>Confirmar Senha: <input type="password" name="confirmPassword" required></label><br>
        <button type="submit">Redefinir Senha</button>
      </form>
    </body>
  `);
}));
//Rota para verificar o token enviado
app.post('/reset-password', (async (req, res) => {
    const { email, token, password, confirmPassword } = req.body;
    // Valida se todos os campos foram enviados
    if (!email || !token || !password || !confirmPassword) {
        return res.status(400).send("Todos os campos são obrigatórios.");
    }
    if (password !== confirmPassword) {
        return res.status(400).send("As senhas não coincidem.");
    }
    // Verifica se o token é válido (sua função de validação deve retornar true ou false)
    const isValid = await verifyResetToken(email, token);
    if (!isValid) {
        return res.status(400).send("Token inválido ou expirado.");
    }
    // Atualiza a senha do usuário (assegure-se de que a função updatePassword aplica o hash)
    await updatePassword(email, password);
    res.send("Senha redefinida com sucesso! <a href='/login'>Fazer login</a>");
}));
// Rota para autenticar um usuário
app.post('/auth', (async (req, res) => {
    // Extrai o e-mail e a senha enviados pelo cliente no corpo da requisição
    const { email, password } = req.body;
    try {
        // Chama a função authenticateUser para buscar e verificar o usuário no banco de dados
        const data = await authenticateUser(email, password);
        // Define o usuário na sessão
        req.session.user = {
            name: data.name,
            email: data.email,
        };
        // Se a autenticação for bem-sucedida, envia uma resposta de boas-vindas
        res.send(`
      <head>
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body> 
        <h2>Bem-vindo, ${data.name}!</h2>
        <a href="/settings">Ir para Configurações</a><br>
        <a href="/logout">Sair</a><br>
      </body>
    `);
    }
    catch (err) {
        // Registra o erro no console para ajudar na depuração
        console.error(err);
        // Retorna um erro interno (500) com a mensagem apropriada
        res.status(500).send(err instanceof Error ? err.message : 'Erro inesperado');
    }
}));
//Rota para exibir o formulário para atualizar os dados do usuário
app.get('/settings', isAuthenticated, (async (req, res) => {
    res.send(`
    <head>
      <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
      <h2>Dados do Usuário</h2>
      <form action="/update" method="POST">
        <label>Nome: <input type="text" name="name" required></label><br>
        <label>Email: <input type="email" name="email" required></label><br>
        <label>Data de Nascimento: <input type="date" name="birthdate" required></label><br>
        <label>Senha: <input type="password" name="password" required></label><br>
        <label>Confirmar Senha: <input type="password" name="confirmPassword" required></label><br>
        <button type="submit">Atualizar</button>
        <a href="/delete">deletar conta</a>
      </form>
    </body>
  `);
}));
// Rota  para atualizar os dados do usuário
app.post('/update', (async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;
    if (!name || !email || !password || !confirmPassword) {
        return res.status(400).send('Todos os campos são obrigatórios');
    }
    if (!validator.isEmail(email)) {
        return res.status(400).send('Formato inválido de e-mail');
    }
    if (password !== confirmPassword) {
        return res.status(400).send('As senhas não coincidem');
    }
    try {
        await updateUser(email, name, password);
        res.send(`
      <head>
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body>
        <h2>Conta atualizada com sucesso!</h2>
        <a href="/settings">Ir para Configurações</a>
      </body>
    `);
    }
    catch (err) {
        if (err instanceof Error && err.message.includes("User not found")) {
            return res.status(404).send("Usuário não encontrado.");
        }
        res.status(500).send(err instanceof Error ? err.message : 'Erro inesperado');
    }
}));
// Rota para exibir a confirmação de exclusão de conta
app.get('/delete', (req, res) => {
    res.send(`
    <head>
      <link rel="stylesheet" href="/styles.css">
    </head>

    <body>
        <h2>Deletar Conta</h2>
        <p style="color: red;">Atenção: Este processo é irreversível! Todos os seus dados serão apagados permanentemente.</p>
        <form action="/delete" method="POST">
          <label>Email: <input type="email" name="email" required></label><br>
          <button type="submit" style="background-color: red; color: white;">Confirmar Exclusão</button>
          <a href="/settings">Cancelar</a>
        </form>
    </body>
  `);
});
// Rota para deletar o usuário
app.post('/delete', (async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).send("O e-mail é obrigatório para excluir a conta.");
    }
    try {
        await deleteUser(email);
        res.send(`
      <head>
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body>
          <h2>Conta deletada com sucesso!</h2>
          <p style="color: red;">Todos os seus dados foram permanentemente removidos.</p>
          <a href="/">Voltar à Página Inicial</a>
      </body>
    `);
    }
    catch (error) {
        res.status(500).send(error instanceof Error ? error.message : "Erro inesperado ao excluir a conta.");
    }
}));
// Rota de logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Erro ao encerrar a sessão');
        }
        res.redirect('/login');
    });
});
// Start the express server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
