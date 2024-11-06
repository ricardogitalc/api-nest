// src/shared/exceptions/filters/all-exceptions.filter.ts
import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { IHttpExceptionResponse } from '../interfaces/http-exception-response.interface';
import { Logger } from '@nestjs/common';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name);

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const message =
      exception instanceof HttpException
        ? exception.getResponse()
        : 'Erro interno do servidor';

    const errorResponse: IHttpExceptionResponse = {
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      error: HttpStatus[status],
      message: this.getErrorMessage(message),
      details: this.getErrorDetails(exception),
    };

    // Log estruturado
    this.logger.error({
      ...errorResponse,
      method: request.method,
      headers: request.headers,
      body: request.body,
      stack: exception instanceof Error ? exception.stack : undefined,
    });

    response.status(status).json(errorResponse);
  }

  private getErrorMessage(message: any): string | string[] {
    if (typeof message === 'string') {
      return message;
    }
    if (message?.message) {
      return Array.isArray(message.message)
        ? message.message
        : [message.message];
    }
    return ['Um erro inesperado ocorreu'];
  }

  private getErrorDetails(exception: unknown): Record<string, any> | undefined {
    if (exception instanceof HttpException) {
      const response = exception.getResponse();
      if (typeof response === 'object') {
        const { message, ...details } = response as any;
        return Object.keys(details).length > 0 ? details : undefined;
      }
    }
    return undefined;
  }
}
