import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
const prisma = new PrismaClient();
// Testar conexão
export async function testConnection() {
    try {
        await prisma.$connect();
        console.log("✅ Conexão com o banco de dados estabelecida com sucesso!");
    }
    catch (error) {
        console.error("❌ Erro ao conectar ao banco de dados:", error);
    }
}
// Criar usuário
export async function createUser(name, email, birthdate, password, verificationToken) {
    // Verifica se o usuário já existe
    const existingUser = await prisma.user.findUnique({
        where: { email },
    });
    //Verifica se o usuário existe no banco
    if (existingUser) {
        throw new Error("E-mail já cadastrado.");
    }
    // Hash da senha
    const hashedPassword = await bcrypt.hash(password.trim(), 10);
    return await prisma.user.create({
        data: {
            name,
            email,
            birthdate: new Date(birthdate),
            password: hashedPassword, // Armazenando a senha hasheada no banco // Agora está sendo salvo corretamente
            verified: false,
            verificationToken // Adiciona um campo para controle
        },
    });
}
export async function verifyAccount(verificationToken, email) {
    try {
        // Busca o usuário com o token fornecido
        const user = await prisma.user.findUnique({
            where: { email, verificationToken },
        });
        // Valida a existência do usuário
        if (!user) {
            throw new Error("Token inválido ou expirado");
        }
        console.log("passei aqui");
        // Atualiza o usuário
        const updatedUser = await prisma.user.update({
            where: { email },
            data: {
                verified: true
            },
        });
        console.log('Conta atualizada:', updatedUser);
        return updatedUser;
    }
    catch (error) {
        console.error('Erro ao verificar conta:', error);
        throw error; // Propaga o erro para ser tratado na rota
    }
}
// Autenticar usuário
export async function authenticateUser(email, password) {
    // Buscar o usuário no banco de dados
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
        throw new Error("Usuário não encontrado");
    }
    // Comparar a senha fornecida com a senha armazenada no banco de dados
    const passwordMatch = await bcrypt.compare(password.trim(), user.password);
    if (!passwordMatch) {
        throw new Error("Senha incorreta");
    }
    return user;
}
// Atualizar usuário
export async function updateUser(email, name, password) {
    const hashedPassword = await bcrypt.hash(password, 10);
    return await prisma.user.update({
        where: { email },
        data: { name, password: hashedPassword }
    });
}
// Deletar usuário
export async function deleteUser(email) {
    return await prisma.user.delete({ where: { email } });
}
// Salvar token de redefinição de senha
export async function saveResetToken(email, token) {
    const expires_at = new Date();
    expires_at.setHours(expires_at.getHours() + 1);
    return await prisma.passwordResets.upsert({
        where: { email },
        update: { token, expires_at },
        create: { email, token, expires_at },
    });
}
// Verificar token de redefinição de senha
export async function verifyResetToken(email, token) {
    const resetRecord = await prisma.passwordResets.findUnique({ where: { email } });
    if (!resetRecord || resetRecord.token !== token || resetRecord.expires_at < new Date()) {
        return false;
    }
    return true;
}
// Atualizar senha
export async function updatePassword(email, newPassword) {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await prisma.user.update({
        where: { email },
        data: { password: hashedPassword }
    });
    await prisma.passwordResets.delete({ where: { email } });
}
// Buscar usuário por e-mail
export async function getUserByEmail(email) {
    return await prisma.user.findUnique({ where: { email } });
}
