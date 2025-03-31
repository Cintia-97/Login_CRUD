import Express from 'express';
const app = Express();
const port = process.env.PORT || 3000;
app.use(Express.json());
app.use(Express.urlencoded({ extended: true }));
// Simulação de banco de dados temporário
const users = [];
// Rota para exibir a tela de escolha entre Login e Criar Conta
app.get('/', (_req, res) => {
    res.send(`
    <h2>Welcome</h2>
    <a href="/register">Create Account</a> | <a href="/login">Login</a>
  `);
});
// Rota para exibir o formulário de criação de conta
app.get('/register', (_req, res) => {
    res.send(`
    <h2>Create User</h2>
    <form action="/users" method="POST">
      <label>Name: <input type="text" name="name" required></label><br>
      <label>Email: <input type="email" name="email" required></label><br>
      <label>Birthdate: <input type="date" name="birthdate" required></label><br>
      <label>Password: <input type="password" name="password" required></label><br>
      <label>Confirm Password: <input type="password" name="confirmPassword" required></label><br>
      <button type="submit">Create</button>
    </form>
  `);
});
// Rota para exibir o formulário de login
app.get('/login', (_req, res) => {
    res.send(`
    <h2>Login</h2>
    <form action="/auth" method="POST">
      <label>Email: <input type="email" name="email" required></label><br>
      <label>Password: <input type="password" name="password" required></label><br>
      <button type="submit">Login</button>
    </form>
  `);
});
// Rota para criar um novo usuário (Create do CRUD)
app.post('/users', (req, res) => {
    const { name, email, birthdate, password, confirmPassword } = req.body;
    if (!name || !email || !birthdate || !password || !confirmPassword) {
        return res.status(400).send('All fields are required');
    }
    if (password !== confirmPassword) {
        return res.status(400).send('Passwords do not match');
    }
    users.push({ name, email, birthdate, password });
    res.send(`User ${name} created successfully! <a href="/">Back</a>`);
});
// Rota para autenticar um usuário (Login)
app.post('/auth', (req, res) => {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email && u.password === password);
    if (!user) {
        return res.status(401).send('Invalid email or password');
    }
    res.send(`
    <h2>Welcome, ${user.name}!</h2>
    <a href="/settings">Go to Settings</a>
  `);
});
// Rota para exibir a página de configurações
app.get('/settings', (req, res) => {
    const user = users[0]; // Assume user is already authenticated (implement session/cookies for actual cases)
    res.send(`
    <h2>Settings</h2>
    <p><strong>Name:</strong> ${user.name}</p>
    <p><strong>Email:</strong> ${user.email}</p>
    <p><strong>Birthdate:</strong> ${user.birthdate}</p>
    <form action="/update" method="POST">
      <h3>Update Information</h3>
      <label>Name: <input type="text" name="name" value="${user.name}" required></label><br>
      <label>Email: <input type="email" name="email" value="${user.email}" required></label><br>
      <label>Birthdate: <input type="date" name="birthdate" value="${user.birthdate}" required></label><br>
      <label>Password: <input type="password" name="password" value="${user.password}" required></label><br>
      <label>Confirm Password: <input type="password" name="confirmPassword" value="${user.password}" required></label><br>
      <button type="submit">Update</button>
    </form>
    <form action="/confirm-delete" method="GET">
      <button type="submit">Delete Account</button>
      <a href="/">Cancel</a>
    </form>
  `);
});
// Rota para atualizar os dados do usuário
app.post('/update', (req, res) => {
    const { name, email, birthdate, password, confirmPassword } = req.body;
    if (!name || !email || !birthdate || !password || !confirmPassword) {
        return res.status(400).send('All fields are required');
    }
    if (password !== confirmPassword) {
        return res.status(400).send('Passwords do not match');
    }
    const user = users[0]; // Assume user is already authenticated (implement session/cookies for actual cases)
    user.name = name;
    user.email = email;
    user.birthdate = birthdate;
    user.password = password;
    res.send(`
    <h2>Account Updated Successfully!</h2>
    <a href="/settings">Go to Settings</a>
  `);
});
// Rota para exibir a página de confirmação de exclusão
app.get('/confirm-delete', (_req, res) => {
    res.send(`
    <h2>Confirm Account Deletion</h2>
    <form action="/delete" method="POST">
      <label>Email: <input type="email" name="email" required></label><br>
      <label>Password: <input type="password" name="password" required></label><br>
      <p>Are you sure you want to delete your account? This action cannot be undone.</p>
      <button type="submit">Delete Account</button>
      <a href="/">Cancel</a>
    </form>
  `);
});
// Rota para deletar um usuário
app.post('/delete', (req, res) => {
    const { email, password } = req.body;
    const userIndex = users.findIndex(u => u.email === email && u.password === password);
    if (userIndex === -1) {
        return res.status(401).send('Invalid credentials');
    }
    users.splice(userIndex, 1);
    res.send('Account deleted successfully. <a href="/">Back</a>');
});
// Start the express server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
