import express, { Request, Response } from 'express';
import dotenv from 'dotenv';
import cookieparser from 'cookie-parser';
import cors from 'cors';
import helloWorldRouter from './routes/helloWorld';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000

// middlewares
app.use(cors())
app.use(express.json());
app.use(cookieparser());

// end points
app.use("/api/helloworld", helloWorldRouter)
app.get("/api", (req: Request, res: Response): any => {
  return res.send("Hello World");
});

app.listen(port, () => {
    console.log(`Listening To The Port : ${port}`);
})
