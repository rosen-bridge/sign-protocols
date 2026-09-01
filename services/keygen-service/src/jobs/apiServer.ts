import rateLimit from '@fastify/rate-limit';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import { TypeBoxTypeProvider } from '@fastify/type-provider-typebox';
import fastify, { FastifyInstance } from 'fastify';

import { DefaultLogger } from '@rosen-bridge/abstract-logger';

import { keygenRoute } from '../api/keygen';
import { p2pRoutes } from '../api/p2p';
import Configs from '../configs/configs';

const logger = DefaultLogger.getInstance().child(import.meta.url);

/**
 * initialize api server
 * setup swagger on it
 * register all routers
 * then start it
 */
let apiServer: FastifyInstance;
const initApiServer = async () => {
  apiServer = fastify({
    bodyLimit: Configs.apiBodyLimit,
  }).withTypeProvider<TypeBoxTypeProvider>();

  await apiServer.register(swagger, {
    openapi: {
      components: {
        securitySchemes: {
          apiKey: {
            type: 'apiKey',
            name: 'Api-Key',
            in: 'header',
          },
        },
      },
    },
  });

  await apiServer.register(swaggerUi, {
    routePrefix: '/swagger',
    uiConfig: {
      docExpansion: 'full',
      deepLinking: false,
    },
    uiHooks: {
      onRequest: function (request, reply, next) {
        next();
      },
      preHandler: function (request, reply, next) {
        next();
      },
    },
    staticCSP: true,
    transformStaticCSP: (header) => header,
    transformSpecification: (swaggerObject) => {
      return swaggerObject;
    },
    transformSpecificationClone: true,
  });

  await apiServer.register(rateLimit, {
    max: Configs.apiMaxRequestsPerMinute,
    timeWindow: '1 minute',
  });

  await apiServer.register(p2pRoutes);
  await apiServer.register(keygenRoute);
  apiServer.get('/', (request, reply) => {
    reply.redirect('/swagger');
  });
  const port = Configs.apiPort;
  const host = Configs.apiHost;

  await apiServer.listen({ host, port });
  logger.info(`api service started at http://${host}:${port}`);
};

export { initApiServer, apiServer };
