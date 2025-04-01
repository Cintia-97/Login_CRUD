// src/types/express-session.d.ts

import { SessionData } from 'express-session';

declare module 'express-session' {
  interface Session {
    user?: {  // A propriedade 'user' pode ser um objeto ou undefined
      email: string;
      name: string;
      // Você pode adicionar mais propriedades, conforme necessário
    };
  }
}
