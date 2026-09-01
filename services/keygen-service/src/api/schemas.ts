import { TypeBoxTypeProvider } from '@fastify/type-provider-typebox';
import { Type } from '@sinclair/typebox';
import { FastifyBaseLogger, FastifyInstance } from 'fastify';
import { IncomingMessage, Server, ServerResponse } from 'http';

export type FastifySeverInstance = FastifyInstance<
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  Server<any, any>,
  IncomingMessage,
  ServerResponse<IncomingMessage>,
  FastifyBaseLogger,
  TypeBoxTypeProvider
>;

export const MessageResponseSchema = Type.Object({
  message: Type.String(),
});
