# LOGIN-CRUD

Projeto fullstack com sistema de autenticação, validação de conta via e-mail e operações CRUD para gerenciamento de usuários.

## 🛠 Tecnologias Utilizadas

- **Node.js** com **Express**
- **TypeScript**
- **SQLite** ou **PostgreSQL/MySQL** (adaptável)
- **Nodemailer** (validação de conta por e-mail)
- **Handlebars** para mensagens renderizadas
- **bcrypt** para criptografia de senhas
- **dotenv** para variáveis de ambiente
- **Validator** para validações de entrada
- HTML/CSS responsivo (páginas como login, registro, deletar conta)

## 🚀 Funcionalidades

- [x] Cadastro de usuário com validação de e-mail
- [x] Validação de senha (mín. 8 caracteres + caractere especial)
- [x] Login com validação de credenciais
- [x] CRUD de usuários (Create, Read, Update, Delete)
- [x] Exclusão de conta com aviso irreversível
- [x] Estilização com base nas cores `#7fb902` e `#008fb9`

## 📂 Estrutura de Pastas

├── src/ │ ├── routes/ │ ├── controllers/ │ ├── views/ │ ├── public/ │ │ ├── css/ │ └── utils/ ├── .env ├── server.ts ├── package.json


## 🔐 Validação por E-mail

- Ao se cadastrar, o usuário recebe um e-mail com um link de verificação.
- O token é gerado via `crypto.randomBytes`.
- O e-mail é enviado através do `Nodemailer`.

## 📌 Requisitos

- Node.js v18+
- Conta de e-mail configurada para envio (ex: Gmail com senha de app)
- Variáveis de ambiente definidas no `.env`:

```env
EMAIL_USER=seuemail@gmail.com
EMAIL_PASS=suasenhadeapp
APP_DOMAIN=http://localhost:3000

# Instalar dependências
npm install

# Iniciar servidor em desenvolvimento
npm run dev

# Compilar TypeScript
npm run build


