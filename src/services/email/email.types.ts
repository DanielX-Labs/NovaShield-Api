// Authentication workflows provide content without knowing provider details.
export interface SendEmailInput {
  to: string;
  subject: string;
  text: string;
  html: string;
}

// Providers resolve only after accepting the message or reject on failure.
export interface EmailProvider {
  send(input: SendEmailInput): Promise<void>;
}
