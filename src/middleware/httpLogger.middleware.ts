import pinoHttp from "pino-http";
import { logger } from "../config/logger.js";

export const httpLogger = pinoHttp({
  logger,
  customProps(req) {
    return { requestId: req.id };
  },
  // Keep HTTP logs small and exclude request bodies and headers.
  serializers: {
    req(req) {
      return { method: req.method, url: req.url, requestId: req.id };
    },
    res(res) {
      return { statusCode: res.statusCode };
    },
  },
});
