// app.ts
import express, { Request, Response, RequestHandler } from 'express';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { verifyAccount, createUser, authenticateUser , updateUser, deleteUser, saveResetToken, verifyResetToken, updatePassword, getUserByEmail } from './services/postgresService.js';
import validator from 'validator';
import { testConnection } from './services/postgresService.js';
import dotenv from "dotenv";
import session from 'express-session';
import { isAuthenticated } from './middlewares/authMiddleware.js';
import { fileURLToPath } from 'url';
import path, { dirname, join } from 'path';
import https from 'https'; // para que possamos fazer as validações via HTTPS (validação de link)
import fs from 'fs';

//Rota esqueci a senha
import crypto from 'crypto';
import nodemailer from 'nodemailer';

//Minhas informações confidenciais
dotenv.config();

// Testar conexão ao iniciar
testConnection();

const app = express();
const port = process.env.PORT || 3000;
const appdomain = process.env.APP_DOMAIN || 'https://localhost';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const publicPaths = [
  join(__dirname, 'public'),
  join(__dirname, '..', 'public')
];

publicPaths.forEach(publicPath => {
  if (fs.existsSync(publicPath)) {
    app.use(express.static(publicPath));
  }
});

function getTemplatePath(templatePath: string): string {
  const devPath = join(__dirname, '..', 'src', 'templates', templatePath);
  const prodPath = join(__dirname, 'templates', templatePath);

  try {
    fs.accessSync(prodPath);
    return prodPath;
  } catch {
    return devPath;
  }
}

function renderTemplate(templatePath: string): string {
  const fullPath = getTemplatePath(templatePath);
  return fs.readFileSync(fullPath, 'utf-8');
}

//Configuração da sessão
app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {     secure: false, // Defina como true se estiver usando HTTPS
                maxAge: 24 * 60 * 60 * 1000, // 1 dia},
                httpOnly: true
  }
}));

app.use((req, _res, next) => {
  if (!req.session) {
    return next(new Error('Sessão não inicializada'));
  }
  next();
});

// Verifica se estamos em desenvolvimento
const isDev = process.env.NODE_ENV !== 'production';

if (isDev) {
  const certPath = path.join(__dirname, 'cert.pem');
  const keyPath = path.join(__dirname, 'key.pem');
  
  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    console.error('Certificados SSL não encontrados. Usando HTTP em desenvolvimento...');
    app.listen(3000, () => {
      console.log('Servidor HTTP rodando em http://localhost:3000');
    });
  } else {
    const options = {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath)
    };
    https.createServer(options, app).listen(3000, () => {
      console.log('Servidor HTTPS rodando em https://localhost:3000');
    });
  }
} else {
  // Em produção, use HTTPS normalmente (a Vercel já cuida disso)
  app.listen(3000, () => {
    console.log('Servidor pronto para produção');
  });
}

//Para acessar a pasta public (que contem meu css)
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true })); // For form data

declare module 'express-session' {
  interface SessionData {
    user: {
      name: string;
      email: string;
      birthdate: string; 
    };
  }
} 

function renderMessage(type: 'success' | 'error' | 'info', title: string, message: string, backLink: string = '/'): string {
  const template = renderTemplate('messageTemplate.html');
  
  const icons = {
      success: 'fa-check-circle',
      error: 'fa-exclamation-circle',
      info: 'fa-info-circle'
  };
  
  return template
      .replace('{{iconClass}}', type)
      .replace('{{icon}}', icons[type])
      .replace('{{title}}', title)
      .replace('{{message}}', message)
      .replace('{{backLink}}', backLink);
}

// Rota para exibir a tela de escolha entre Login e Criar Conta
app.get('/', async (req: Request, res: Response) => {
  res.send(
        renderTemplate('inicial.html') 
    );
});

// Rota para exibir o formulário de criação de conta
app.get('/register', async (req: Request, res: Response) => {
  res.send(
    renderTemplate('register.html') 
  );
});

app.get('/termos', (req: Request, res: Response) => {
  res.send(renderTemplate('termos.html'));
});

//Rota de Login do usuário
app.get('/login', async (req: Request, res: Response) => {
  res.send(
    renderTemplate('login.html') 
  );
});

//Para criar um novo usuário e chama a função de conexão com o banco de dados
app.post('/users', (async (req: Request, res: Response) => {
  const { name, email, birthdate, password, confirmPassword, terms } = req.body;

  if (!name || !email || !birthdate || !password || !confirmPassword) {
    return res.status(400).send(renderMessage(
      'error',
      'Campos obrigatórios',
      'Todos os campos são obrigatórios',
      '/register'
    ));
  }

  if (!terms) {
    return res.send(renderMessage(
      'error',
      'Erro',
      'Você precisa aceitar os Termos de Uso para criar uma conta.'
    ));
  }

  if (!validator.isEmail(email)) {
    return res.status(400).send(renderMessage(
      'error',
      'E-mail inválido',
      'O formato do e-mail é inválido',
      '/register'
    ));
  }

  if (password.length <= 8 || !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    return res.status(400).send(renderMessage(
      'error',
      'Senha fraca',
      'A senha deve ter pelo menos 8 caracteres e conter pelo menos um caractere especial.',
      '/register'
    ));
  }

  if (password !== confirmPassword) {
    return res.status(400).send(renderMessage(
      'error',
      'Senhas não conferem',
      'As senhas digitadas não são iguais',
      '/register'
    ));
  }

  // Gerar um token de verificação
  const verificationToken = crypto.randomBytes(32).toString('hex');
  console.log("token gerado:",verificationToken)

  // Envia e-mail de verificação
  const verificationLink = `${appdomain}/validado?token=${verificationToken}&email=${email}`;
  console.log("verificationLink:", verificationLink)
  // Configuração do envio de e-mail
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,  //  email
      pass: process.env.EMAIL_PASS   //  senha de app
    }
  });
    
    const mailOptions = {
      from: process.env.EMAIL_USER, //  email
      to: email,
      subject: 'Validação da conta',
      text: `Clique no link para validar a sua conta:
      
      ${verificationLink}`
    }

  try { 
    const user = await getUserByEmail(email);

    // Verifica se o usuário existe
    if (user) {   
      return res.status(401).send(renderMessage(
        'info',
        'Email cadastrado',
        'A conta já está cadastrada, vamos fazer o login?',
        '/login'
      ));
    }
    
    await transporter.sendMail(mailOptions);
    await createUser(name, email, birthdate, password, verificationToken);
    
    return res.status(201).send(renderMessage(
      'success',
      'Conta criada com sucesso!',
      'Sua conta foi criada com sucesso. Verifique seu e-mail para aprovar a conta!',
      '/login'
    ));

  } catch (err) {   
    if (err instanceof Error && err.message.includes("Email already registered")) {
      console.log("conta já existe")
      return res.status(400).send(renderMessage(
        'error',
        'Erro ao criar conta',
        err.message || 'Ocorreu um erro ao tentar criar sua conta',
        '/register'
      ));
    }
    res.status(500).send(err instanceof Error ? err.message : 'Unexpected error');
  }
}) as RequestHandler) ;

//Valida a criação da conta
app.get('/validado',(async (req: Request, res: Response) => {
  const { token: verificationToken, email } = req.query;
  console.log("Email recebido:", email);  // Verifique se o email está sendo passado corretamente
  console.log("Token recebido:", verificationToken);
  console.log("validado")
  console.log("validado")

  if (!verificationToken || !email) {
    return res.status(400).send(renderMessage(
      'error',
      'Dados incompletos',
      'Token e e-mail são necessários para validação',
      '/register'
    ));
  }

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Validação de Conta</title>
      <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
      <div class="container">
        <h2>Validação de Conta</h2>
        <form action="/validado" method="POST">
          <input type="hidden" name="email" value="${email}">
          <input type="hidden" name="token" value="${verificationToken}">
          <button type="submit">Confirmar Validação</button>
        </form>
      </div>
    </body>
    </html>
  `);
}) as RequestHandler);

//Solicita a validação no banco de dados
app.post('/validado', (async (req: Request, res: Response) => {
  const { email, token: verificationToken } = req.body;
  
  try {
      if (!email || !verificationToken) {
          throw new Error('Email e token são obrigatórios');
      }

      console.log(`Tentando validar conta para ${email} com token ${verificationToken}`);
      
      await verifyAccount(verificationToken, email);
      
      return res.send(renderMessage(
          'success',
          'Conta validada!',
          'Sua conta foi ativada com sucesso. Você já pode fazer login.',
          '/login'
      ));

  } catch (error: any) {
      console.error('Erro na rota de validação:', error);
      res.status(400).send(renderMessage(
          'error',
          'Falha na validação',
          error.message || 'Ocorreu um erro ao validar sua conta',
          '/register'
      ));
  }
}) as RequestHandler);

//Formulário de reset de senha
app.get('/forgot-password', (async (req: Request, res: Response) => {
  res.send(
    renderTemplate('forgot-password.html') 
  );
}));

//Rota para gerar o token e validar o e-mail
app.post('/forgot-password', (async (req: Request, res: Response) => {
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
  console.log("token gerado:",token)

  // Salvar o token no banco com validade (ex: 1 hora)
  await saveResetToken(email, token);

  // Criar link para redefinição
  const resetLink = `${appdomain}/reset-password?token=${token}&email=${email}`;

  // Configuração do envio de e-mail
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,  //  email
      pass: process.env.EMAIL_PASS   //  senha de app
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
      return res.status(200).send(renderMessage(
        'success',
        'E-mail enviado com sucesso!',
        'Verifique sua caixa de entrada',
        '/Login'
      ));
  } catch (error) {
    res.status(500).send("Erro ao enviar e-mail.");
  }
}) as RequestHandler);

//Formulário para redefinir a senha após o envio do token
app.get('/reset-password',(async (req: Request, res: Response) => {
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
}) as RequestHandler);

//Rota para verificar o token enviado
app.post('/reset-password', (async (req: Request, res: Response) => {
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
}) as RequestHandler);

// Rota para autenticar um usuário
app.post('/auth', (async (req: Request, res: Response) => {
  // Extrai o e-mail e a senha enviados pelo cliente no corpo da requisição
  const { email, password } = req.body;

    // Validação básica dos campos
    if (!email || !password) {
      return res.status(400).send(renderMessage(
        'error',
        'Campos obrigatórios',
        'E-mail e senha são obrigatórios',
        '/login'
      ));
    }
  
    // Validação do formato do e-mail
    if (!validator.isEmail(email)) {
      return res.status(400).send(renderMessage(
        'error',
        'E-mail inválido',
        'O formato do e-mail é inválido',
        '/login'
      ));
    }

  try {
        const user = await getUserByEmail(email);

        // Verifica se o usuário existe
        if (!user) {
          
          return res.status(401).send(renderMessage(
            'error',
            'Usuário não encontrado',
            'Nenhuma conta encontrada com este e-mail',
            '/login'
          ));
        }
        // Verifica se a conta está validado
        if (user.verified === false ) {
          console.log("usuário verificado?",user.verified)
          return res.status(403).send(renderMessage(
            'error',
            'Conta não verificada',
            'Por favor, verifique seu e-mail para ativar sua conta',
            '/login'
          ));
        }

        // Chama a função authenticateUser para buscar e verificar o usuário no banco de dados
       await authenticateUser(email, password); 
       
       req.session.user = {
        name: user.name,
        email: user.email,
        birthdate: user.birthdate ? user.birthdate.toISOString() : '' // 
      };

      req.session.save(err => {
        if (err) {
          console.error('Erro ao salvar sessão:', err);
          return res.status(500).send('Erro interno');
        }
        res.redirect('/principal');
      });
  } catch (err: any) {
    console.error(err);
    
    let errorMessage = 'E-mail ou senha incorretos';
    if (err.message.includes('Usuário não encontrado') || err.message.includes('Senha inválida')) {
      errorMessage = 'Credenciais inválidas';
    }

    return res.status(401).send(renderMessage(
      'error',
      'Falha no login',
      errorMessage,
      '/login'
    ));
  }

})as RequestHandler);

app.get('/test-session', (req, res) => {
  console.log('Sessão atual:', req.session);
  res.json({
    session: req.session,
    user: req.session.user
  });
});

//Rota para exibir o formulário para atualizar os dados do usuário
app.get('/settings', isAuthenticated, (async (req: Request, res: Response) => {

  if (!req.session.user) {
    console.log("mensagem de erro")
    return res.redirect('/login');
  }

  // Formata a data apenas para exibição
  const formattedBirthdate = req.session.user.birthdate 
  ? formatDateToDDMMAAAA(new Date(req.session.user.birthdate))
  : '';

  // Carrega o template e substitui os placeholders
  let template = renderTemplate('settings.html');
  template = template
    .replace('{{name}}', req.session.user.name || '')
    .replace('{{email}}', req.session.user.email || '')
    .replace('{{birthdate}}', formattedBirthdate);
  res.send(template);

}) as RequestHandler);

// Função auxiliar para formatar a data
function formatDateToDDMMAAAA(date: Date): string {
  const day = date.getDate().toString().padStart(2, '0');
  const month = (date.getMonth() + 1).toString().padStart(2, '0');
  const year = date.getFullYear();
  return `${day}-${month}-${year}`;
}

//Rota para minha página principal
app.get('/principal', isAuthenticated, (async(req: Request, res: Response) => {
  res.send(
    renderTemplate('home.html') 
  );
}) as RequestHandler);

// Rota  para atualizar os dados do usuário
app.post('/update', isAuthenticated, (async (req: Request, res: Response) => {
  const {name, password, confirmPassword} = req.body;
  const userEmail = req.session.user?.email;

  // Validações básicas
  if (!userEmail) {
    return res.status(401).send(renderMessage(
      'error',
      'Não autorizado',
      'Sessão inválida ou expirada',
      '/login'
    ));
  }

  // Valida se pelo menos um campo foi enviado para atualização
  if (!name && !password) {
    return res.status(400).send(renderMessage(
      'error',
      'Dados insuficientes',
      'Informe pelo menos um campo para atualização (nome ou senha)',
      '/settings'
    ));
  }

  // Validação específica para senha (se foi enviada)
  if (password) {
    if (password !== confirmPassword) {
      return res.status(400).send(renderMessage(
        'error',
        'Senhas não coincidem',
        'As senhas digitadas não são iguais',
        '/settings'
      ));    
    }

    if (password.length < 8 || !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      return res.status(400).send(renderMessage(
        'error',
        'Senha fraca',
        'A senha deve ter pelo menos 8 caracteres e conter pelo menos um caractere especial.',
        '/settings'
      ));
    }
  }

  try {
    // Atualiza apenas os campos fornecidos
    await updateUser(userEmail, name, password || undefined);

    // Atualiza a sessão com o novo nome
    if (req.session.user && name) {
      req.session.user.name = name;
    }
    
    return res.status(200).send(renderMessage(
      'success',
      'Dados atualizados',
      'Seus dados foram atualizados com sucesso!',
      '/principal'
    ));
  } catch (err) {
    if (err instanceof Error && err.message.includes("User not found")) {
      return res.status(404).send(renderMessage(
        'error', 
        'Erro na atualização',
        err.message || 'Ocorreu um erro ao atualizar seus dados',
        '/settings'
      ));
    }
    res.status(500).send(renderMessage(
      'error',
      'Erro no servidor',
      'Ocorreu um erro inesperado',
      '/settings'
    ));
  }
}) as RequestHandler);

// Rota para exibir a confirmação de exclusão de conta
app.get('/delete', isAuthenticated, (req: Request, res: Response) => {
  res.send(
    renderTemplate('delete.html')
  );
});

// Rota para deletar o usuário
app.post('/delete', isAuthenticated, (async (req: Request, res: Response) => {
  const { email } = req.body;
  const user = await getUserByEmail(email);

  if (!email) {
    return res.status(400).send(renderMessage(
      'error',
      'erro no email',
      'O e-mail é obrigatório para excluir a conta.',
      '/settings'
    ));
  }

    // Verifica se o e-mail enviado é o mesmo do usuário logado
    if (email !== user) {
      return res.status(403).send(renderMessage(
        'error',
        'Verifique o e-mail',
        'O e-mail fornecido precisa ser o utilizado na conta',
        '/delete'
      ));
    }

  try {
    await deleteUser(email);
    return res.status(200).send(renderMessage(
      'success',
      'Conta deletada com sucesso!',
      'Todos os seus dados foram permanentemente removidos.',
      '/Login'
    ));
  } catch (error) {
    // Verifica se é um erro do Prisma (P2025: Registro não encontrado)
    if (error instanceof PrismaClientKnownRequestError && error.code === 'P2025') {
      return res.status(400).send(renderMessage(
        'error',
        'Verifique o e-mail',
        'O e-mail fornecido precisa ser o utilizado na conta',
        '/delete'
      ));
    }

    // Para demais erros inesperados
    res.status(500).send(error instanceof Error ? error.message : "Erro inesperado ao excluir a conta.");

  }
}) as RequestHandler);

// Rota de logout
app.get('/logout', isAuthenticated, (req: Request, res: Response) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Erro ao encerrar a sessão');
    }
    res.redirect('/login');
  });
});

// Verifica em qual porta e domain o servidor esta rodando
app.listen(port, () => {
  console.log(`Server is running on ${appdomain}:${port}/`);
});

//Para fazer o download da carta de apresentação
app.get('/download-curriculo', (req, res) => {
  res.download('/public/pdf/Cintia Reis Gonsalez Souza.pdf', 'Curriculo.pdf');
});

app.get('/download-carta', (req, res) => {
  res.download('/public/pdf/Carta_de_apresentacao', 'Cartadeapresentacao.pdf');
});


export default app;