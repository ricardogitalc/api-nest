// src/shared/exceptions/interfaces/http-exception-response.interface.ts
export interface IHttpExceptionResponse {
  timestamp: string;
  path: string;
  statusCode: number;
  error: string;
  message: string | string[];
  details?: Record<string, any>;
}
