import type { RequestHandler } from "express";
import { registrationService, type createRegistrationService } from "../services/auth/registration.service.js";
import { securityContext } from "../services/security/securityEvent.service.js";

// Controllers own the HTTP contract; workflows and transactions remain in services.
export function createRegistrationControllers(
  service: ReturnType<typeof createRegistrationService> = registrationService,
): { register: RequestHandler; resend: RequestHandler; verify: RequestHandler } {
  return {
    register: async (req, res) => {
      await service.register(req.body, securityContext(req));
      res.status(202).json({ success: true,
        message: "If eligible, a verification code will be sent to this address.",
        requestId: req.id });
    },
    resend: async (req, res) => {
      await service.resend(req.body.email, securityContext(req));
      res.status(202).json({ success: true,
        message: "If eligible, a verification code will be sent to this address.",
        requestId: req.id });
    },
    verify: async (req, res) => {
      await service.verify(
        req.body.challengeId, req.body.otp, securityContext(req), req.body.password,
      );
      res.status(200).json({ success: true, message: "Email verified.", requestId: req.id });
    },
  };
}
