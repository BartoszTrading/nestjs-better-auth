import { createParamDecorator } from "@nestjs/common";
import { CustomDecorator } from "@nestjs/common";
import { createAuthMiddleware } from "better-auth/api";
/**
* Marks a route or a controller as public, allowing unauthenticated access.
* When applied, the AuthGuard will skip authentication checks.
*/
declare const Public: () => CustomDecorator<string>;
/**
* Marks a route or a controller as having optional authentication.
* When applied, the AuthGuard will allow the request to proceed
* even if no session is present.
*/
declare const Optional: () => CustomDecorator<string>;
/**
* Parameter decorator that extracts the user session from the request.
* Provides easy access to the authenticated user's session data in controller methods.
*/
declare const Session: ReturnType<typeof createParamDecorator>;
/**
* Represents the context object passed to hooks.
* This type is derived from the parameters of the createAuthMiddleware function.
*/
type AuthHookContext = Parameters<Parameters<typeof createAuthMiddleware>[0]>[0];
/**
* Registers a method to be executed before a specific auth route is processed.
* @param path - The auth route path that triggers this hook (must start with '/')
*/
declare const BeforeHook: (path: `/${string}`) => CustomDecorator<symbol>;
/**
* Registers a method to be executed after a specific auth route is processed.
* @param path - The auth route path that triggers this hook (must start with '/')
*/
declare const AfterHook: (path: `/${string}`) => CustomDecorator<symbol>;
/**
* Class decorator that marks a provider as containing hook methods.
* Must be applied to classes that use BeforeHook or AfterHook decorators.
*/
declare const Hook: () => ClassDecorator;
import { Auth } from "better-auth";
/**
* NestJS service that provides access to the Better Auth instance
* Use generics to support auth instances extended by plugins
*/
declare class AuthService<T extends {
	api: T["api"]
} = Auth> {
	private readonly auth;
	constructor(auth: T);
	/**
	* Returns the API endpoints provided by the auth instance
	*/
	get api(): T["api"];
	/**
	* Returns the complete auth instance
	* Access this for plugin-specific functionality
	*/
	get instance(): T;
}
import { CanActivate, ExecutionContext } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { Auth as Auth2 } from "better-auth";
import { getSession } from "better-auth/api";
/**
* Type representing a valid user session after authentication
* Excludes null and undefined values from the session return type
*/
type UserSession = NonNullable<Awaited<ReturnType<ReturnType<typeof getSession>>>>;
declare class AuthGuard implements CanActivate {
	private readonly reflector;
	private readonly auth;
	constructor(reflector: Reflector, auth: Auth2);
	/**
	* Validates if the current request is authenticated
	* Attaches session and user information to the request object
	* @param context - The execution context of the current request
	* @returns True if the request is authorized to proceed, throws an error otherwise
	*/
	canActivate(context: ExecutionContext): Promise<boolean>;
}
import { DynamicModule, MiddlewareConsumer, NestModule, OnModuleInit } from "@nestjs/common";
import { DiscoveryService, HttpAdapterHost, MetadataScanner } from "@nestjs/core";
import { Auth as Auth3 } from "better-auth";
/**
* Configuration options for the AuthModule
*/
type AuthModuleOptions = {
	disableExceptionFilter?: boolean
	disableTrustedOriginsCors?: boolean
	disableBodyParser?: boolean
};
declare class AuthModule implements NestModule, OnModuleInit {
	private readonly auth;
	private readonly discoveryService;
	private readonly metadataScanner;
	private readonly adapter;
	private readonly options;
	private readonly logger;
	constructor(auth: Auth3, discoveryService: DiscoveryService, metadataScanner: MetadataScanner, adapter: HttpAdapterHost, options: AuthModuleOptions);
	onModuleInit(): void;
	configure(consumer: MiddlewareConsumer): void;
	private setupHooks;
	/**
	* Static factory method to create and configure the AuthModule.
	* @param auth - The Auth instance to use
	* @param options - Configuration options for the module
	*/
	static forRoot(auth: any, options?: AuthModuleOptions): DynamicModule;
}
export { UserSession, Session, Public, Optional, Hook, BeforeHook, AuthService, AuthModule, AuthHookContext, AuthGuard, AfterHook };
