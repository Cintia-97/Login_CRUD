// Middleware de autenticação para verificar se o usuário está logado
export const isAuthenticated = (req, res, next) => {
    if (req.session?.user) {
        return next(); // Se o usuário estiver autenticado, permite o acesso à rota
    }
    return res.redirect('/login'); // Se não estiver autenticado, redireciona para a página de login
};
