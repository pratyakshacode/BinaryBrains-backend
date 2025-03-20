import pino from "pino";

const logger = pino(
  { level: "info" }, // Log only "info" level and above
  pino.destination(1)
);

export default logger;