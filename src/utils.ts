import { ArgumentsHost, ExecutionContext } from "@nestjs/common";
import { GqlArgumentsHost, GqlExecutionContext } from "@nestjs/graphql";

/**
 *  Retrieves request object from the ExecutionContext
 *  Supports both HTTP and GraphQL contexts
 */
export function getRequestObject(context: ExecutionContext): any {
  if (context.getType() === 'http') {
    return context.switchToHttp().getRequest();
  }
  return GqlExecutionContext.create(context).getContext().req;
}

export function getResponseObject(host: ArgumentsHost): any {
  const type = host.getType();
  if (type === 'http') {
    return host.switchToHttp().getResponse();
  }
  return GqlArgumentsHost.create(host).getContext().res;
}