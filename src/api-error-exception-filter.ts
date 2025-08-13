import type { ArgumentsHost } from "@nestjs/common";
import { Catch } from "@nestjs/common";
import type { ExceptionFilter } from "@nestjs/common";
import { APIError } from "better-auth/api";
import { getResponseObject } from "./utils.ts";

@Catch(APIError)
export class APIErrorExceptionFilter implements ExceptionFilter {
	catch(exception: APIError, host: ArgumentsHost): void {
		const response = getResponseObject(host);
		const status = exception.statusCode;
		const message = exception.body?.message;

		response.status(status).json({
			statusCode: status,
			message,
		});
	}
}
