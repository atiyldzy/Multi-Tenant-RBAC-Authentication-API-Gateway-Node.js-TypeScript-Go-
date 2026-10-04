import { Router } from 'express';
import { proxyRequestHandler } from '../proxy/proxyEngine.js';

export const proxyRouter = Router();

// Forward all incoming calls under gateway prefix through the dynamic reverse proxy
proxyRouter.use('/*', proxyRequestHandler);
