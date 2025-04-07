import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

// Testar conexão
export async function testConnection() {
  try {
    await prisma.$connect();
    console.log("✅ Conexão com o banco de dados estabelecida com sucesso!");
  } catch (error) {
    console.error("❌ Erro ao conectar ao banco de dados:", error);
  }
}

// Criar usuário
export async function createUser(name: string, email: string, birthdate: string, password: string, verificationToken: string) {
  
  // Hash da senha
  const hashedPassword = await bcrypt.hash(password.trim(), 10);

  return await prisma.user.create({
    data: {
      name,
      email,
      birthdate: new Date(birthdate),
      password: hashedPassword,  // Armazenando a senha hasheada no banco // Agora está sendo salvo corretamente
      verified: false,
      verificationToken  // Adiciona um campo para controle
    },
  });

}

export async function verifyAccount(verificationToken: string, email: string) {
  try {  
      console.log(`Buscando usuário com email: ${email} e token: ${verificationToken}`);
      
      // Busca o usuário apenas pelo email primeiro
      const user = await prisma.user.findUnique({
          where: { email }
      });

      console.log("Usuário encontrado:", user);
      
      if (!user) {
          throw new Error("Nenhum usuário encontrado com este email");
      }

      // Verifica se o token corresponde
      if (user.verificationToken !== verificationToken) {
          console.log(`Token esperado: ${user.verificationToken}`);
          console.log(`Token recebido: ${verificationToken}`);
          throw new Error("Token de verificação inválido");
      }

      // Atualiza o usuário
      const updatedUser = await prisma.user.update({
          where: { email },
          data: { 
              verified: true
          },
      });

      console.log('Conta atualizada com sucesso:', updatedUser);
      return updatedUser;

  } catch (error) {
      console.error('Erro detalhado ao verificar conta:', error);
      throw error;
  }
}

// Autenticar usuário
export async function authenticateUser(email:string, password:string) {
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
export async function updateUser(email: string, name?: string, password?: string) {
  const updateData: { name?: string; password?: string } = {};
  
  // Apenas adiciona ao objeto de atualização o que foi fornecido
  if (name) updateData.name = name;
  
  if (password) {
    const hashedPassword = await bcrypt.hash(password, 10);
    updateData.password = hashedPassword;
  }

  return await prisma.user.update({
    where: { email },
    data: updateData
  });
}

// Deletar usuário
export async function deleteUser(email:string) {
  return await prisma.user.delete({ where: { email } });
}


// Salvar token de redefinição de senha
export async function saveResetToken(email: string, token: string) {
  const expires_at = new Date();
  expires_at.setHours(expires_at.getHours() + 1);

  return await prisma.passwordResets.upsert({
    where: { email },
    update: { token, expires_at },
    create: { email, token, expires_at },
  });
}

// Verificar token de redefinição de senha
export async function verifyResetToken(email:string, token:string) {
  const resetRecord = await prisma.passwordResets.findUnique({ where: { email } });
  if (!resetRecord || resetRecord.token !== token || resetRecord.expires_at < new Date()) {
    return false;
  }
  return true;
}

// Atualizar senha
export async function updatePassword(email:string, newPassword:string) {
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  await prisma.user.update({
    where: { email },
    data: { password: hashedPassword }
  });

  await prisma.passwordResets.delete({ where: { email } });
}

// Buscar usuário por e-mail
export async function getUserByEmail(email:string) {
  return await prisma.user.findUnique({ where: { email } });
}
