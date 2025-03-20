/**
 * This is the dummy router
 */

import express, { Request, Response } from 'express'
import helloWorldMiddleware from '../middlewares/helloWorldMiddleware';
import { helloWorldController } from '../controllers/helloWorldController';
const helloWorldRouter = express.Router();

helloWorldRouter.get('/', helloWorldMiddleware, helloWorldController)

export default helloWorldRouter;