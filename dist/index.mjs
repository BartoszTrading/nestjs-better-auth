import { createRequire } from "node:module";
var __legacyDecorateClassTS = function(decorators, target, key, desc) {
  var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
  if (typeof Reflect === "object" && typeof Reflect.decorate === "function")
    r = Reflect.decorate(decorators, target, key, desc);
  else
    for (var i = decorators.length - 1;i >= 0; i--)
      if (d = decorators[i])
        r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
  return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __legacyDecorateParamTS = (index, decorator) => (target, key) => decorator(target, key, index);
var __legacyMetadataTS = (k, v) => {
  if (typeof Reflect === "object" && typeof Reflect.metadata === "function")
    return Reflect.metadata(k, v);
};

// src/decorators.ts
import { SetMetadata, createParamDecorator } from "@nestjs/common";

// src/symbols.ts
var BEFORE_HOOK_KEY = Symbol("BEFORE_HOOK");
var AFTER_HOOK_KEY = Symbol("AFTER_HOOK");
var HOOK_KEY = Symbol("HOOK");
var AUTH_INSTANCE_KEY = Symbol("AUTH_INSTANCE");
var AUTH_MODULE_OPTIONS_KEY = Symbol("AUTH_MODULE_OPTIONS");

// src/utils.ts
import { GqlArgumentsHost, GqlExecutionContext } from "@nestjs/graphql";
function getRequestObject(context) {
  if (context.getType() === "http") {
    return context.switchToHttp().getRequest();
  }
  return GqlExecutionContext.create(context).getContext().req;
}
function getResponseObject(host) {
  const type = host.getType();
  if (type === "http") {
    return host.switchToHttp().getResponse();
  }
  return GqlArgumentsHost.create(host).getContext().res;
}

// src/decorators.ts
var Public = () => SetMetadata("PUBLIC", true);
var Optional = () => SetMetadata("OPTIONAL", true);
var Session = createParamDecorator((_data, context) => {
  const request = getRequestObject(context);
  return request.session;
});
var BeforeHook = (path) => SetMetadata(BEFORE_HOOK_KEY, path);
var AfterHook = (path) => SetMetadata(AFTER_HOOK_KEY, path);
var Hook = () => SetMetadata(HOOK_KEY, true);
// src/auth-service.ts
import { Inject } from "@nestjs/common";
class AuthService {
  auth;
  constructor(auth) {
    this.auth = auth;
  }
  get api() {
    return this.auth.api;
  }
  get instance() {
    return this.auth;
  }
}
AuthService = __legacyDecorateClassTS([
  __legacyDecorateParamTS(0, Inject(AUTH_INSTANCE_KEY)),
  __legacyMetadataTS("design:paramtypes", [
    typeof T === "undefined" ? Object : T
  ])
], AuthService);
// src/auth-guard.ts
import { Inject as Inject2, Injectable } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { APIError } from "better-auth/api";
import { fromNodeHeaders } from "better-auth/node";
class AuthGuard {
  reflector;
  auth;
  constructor(reflector, auth) {
    this.reflector = reflector;
    this.auth = auth;
  }
  async canActivate(context) {
    const request = getRequestObject(context);
    const session = await this.auth.api.getSession({
      headers: fromNodeHeaders(request.headers)
    });
    request.session = session;
    request.user = session?.user ?? null;
    const isPublic = this.reflector.getAllAndOverride("PUBLIC", [
      context.getHandler(),
      context.getClass()
    ]);
    if (isPublic)
      return true;
    const isOptional = this.reflector.getAllAndOverride("OPTIONAL", [
      context.getHandler(),
      context.getClass()
    ]);
    if (isOptional && !session)
      return true;
    if (!session)
      throw new APIError(401, {
        code: "UNAUTHORIZED",
        message: "Unauthorized"
      });
    return true;
  }
}
AuthGuard = __legacyDecorateClassTS([
  Injectable(),
  __legacyDecorateParamTS(0, Inject2(Reflector)),
  __legacyDecorateParamTS(1, Inject2(AUTH_INSTANCE_KEY)),
  __legacyMetadataTS("design:paramtypes", [
    typeof Reflector === "undefined" ? Object : Reflector,
    typeof Auth === "undefined" ? Object : Auth
  ])
], AuthGuard);
// src/auth-module.ts
import { Inject as Inject3, Logger, Module } from "@nestjs/common";
import {
  APP_FILTER,
  DiscoveryModule,
  DiscoveryService,
  HttpAdapterHost,
  MetadataScanner
} from "@nestjs/core";
import { toNodeHandler } from "better-auth/node";
import { createAuthMiddleware } from "better-auth/plugins";

// src/api-error-exception-filter.ts
import { Catch } from "@nestjs/common";
import { APIError as APIError2 } from "better-auth/api";
class APIErrorExceptionFilter {
  catch(exception, host) {
    const response = getResponseObject(host);
    const status = exception.statusCode;
    const message = exception.body?.message;
    response.status(status).json({
      statusCode: status,
      message
    });
  }
}
APIErrorExceptionFilter = __legacyDecorateClassTS([
  Catch(APIError2)
], APIErrorExceptionFilter);

// src/middlewares.ts
import { Injectable as Injectable2 } from "@nestjs/common";
import * as express from "express";
class SkipBodyParsingMiddleware {
  use(req, res, next) {
    if (req.baseUrl.startsWith("/api/auth")) {
      next();
      return;
    }
    express.json()(req, res, (err) => {
      if (err) {
        next(err);
        return;
      }
      express.urlencoded({ extended: true })(req, res, next);
    });
  }
}
SkipBodyParsingMiddleware = __legacyDecorateClassTS([
  Injectable2()
], SkipBodyParsingMiddleware);

// src/auth-module.ts
var HOOKS = [
  { metadataKey: BEFORE_HOOK_KEY, hookType: "before" },
  { metadataKey: AFTER_HOOK_KEY, hookType: "after" }
];

class AuthModule {
  auth;
  discoveryService;
  metadataScanner;
  adapter;
  options;
  logger = new Logger(AuthModule.name);
  constructor(auth, discoveryService, metadataScanner, adapter, options) {
    this.auth = auth;
    this.discoveryService = discoveryService;
    this.metadataScanner = metadataScanner;
    this.adapter = adapter;
    this.options = options;
  }
  onModuleInit() {
    if (!this.auth.options.hooks)
      return;
    const providers = this.discoveryService.getProviders().filter(({ metatype }) => metatype && Reflect.getMetadata(HOOK_KEY, metatype));
    for (const provider of providers) {
      const providerPrototype = Object.getPrototypeOf(provider.instance);
      const methods = this.metadataScanner.getAllMethodNames(providerPrototype);
      for (const method of methods) {
        const providerMethod = providerPrototype[method];
        this.setupHooks(providerMethod, provider.instance);
      }
    }
  }
  configure(consumer) {
    const trustedOrigins = this.auth.options.trustedOrigins;
    const isNotFunctionBased = trustedOrigins && Array.isArray(trustedOrigins);
    if (!this.options.disableTrustedOriginsCors && isNotFunctionBased) {
      this.adapter.httpAdapter.enableCors({
        origin: trustedOrigins,
        methods: ["GET", "POST", "PUT", "DELETE"],
        credentials: true
      });
    } else if (trustedOrigins && !this.options.disableTrustedOriginsCors && !isNotFunctionBased)
      throw new Error("Function-based trustedOrigins not supported in NestJS. Use string array or disable CORS with disableTrustedOriginsCors: true.");
    if (!this.options.disableBodyParser)
      consumer.apply(SkipBodyParsingMiddleware).forRoutes("*path");
    let basePath = this.auth.options.basePath ?? "/api/auth";
    if (!basePath.startsWith("/")) {
      basePath = `/${basePath}`;
    }
    if (basePath.endsWith("/")) {
      basePath = basePath.slice(0, -1);
    }
    const handler = toNodeHandler(this.auth);
    this.adapter.httpAdapter.getInstance().use(`${basePath}/*path`, (req, res) => {
      req.url = req.originalUrl;
      return handler(req, res);
    });
    this.logger.log(`AuthModule initialized BetterAuth on '${basePath}/*'`);
  }
  setupHooks(providerMethod, providerClass) {
    if (!this.auth.options.hooks)
      return;
    for (const { metadataKey, hookType } of HOOKS) {
      const hookPath = Reflect.getMetadata(metadataKey, providerMethod);
      if (!hookPath)
        continue;
      const originalHook = this.auth.options.hooks[hookType];
      this.auth.options.hooks[hookType] = createAuthMiddleware(async (ctx) => {
        if (originalHook) {
          await originalHook(ctx);
        }
        if (hookPath === ctx.path) {
          await providerMethod.apply(providerClass, [ctx]);
        }
      });
    }
  }
  static forRoot(auth, options = {}) {
    auth.options.hooks = {
      ...auth.options.hooks
    };
    const providers = [
      {
        provide: AUTH_INSTANCE_KEY,
        useValue: auth
      },
      {
        provide: AUTH_MODULE_OPTIONS_KEY,
        useValue: options
      },
      AuthService
    ];
    if (!options.disableExceptionFilter) {
      providers.push({
        provide: APP_FILTER,
        useClass: APIErrorExceptionFilter
      });
    }
    return {
      global: true,
      module: AuthModule,
      providers,
      exports: [
        {
          provide: AUTH_INSTANCE_KEY,
          useValue: auth
        },
        {
          provide: AUTH_MODULE_OPTIONS_KEY,
          useValue: options
        },
        AuthService
      ]
    };
  }
}
AuthModule = __legacyDecorateClassTS([
  Module({
    imports: [DiscoveryModule]
  }),
  __legacyDecorateParamTS(0, Inject3(AUTH_INSTANCE_KEY)),
  __legacyDecorateParamTS(1, Inject3(DiscoveryService)),
  __legacyDecorateParamTS(2, Inject3(MetadataScanner)),
  __legacyDecorateParamTS(3, Inject3(HttpAdapterHost)),
  __legacyDecorateParamTS(4, Inject3(AUTH_MODULE_OPTIONS_KEY)),
  __legacyMetadataTS("design:paramtypes", [
    typeof Auth === "undefined" ? Object : Auth,
    typeof DiscoveryService === "undefined" ? Object : DiscoveryService,
    typeof MetadataScanner === "undefined" ? Object : MetadataScanner,
    typeof HttpAdapterHost === "undefined" ? Object : HttpAdapterHost,
    typeof AuthModuleOptions === "undefined" ? Object : AuthModuleOptions
  ])
], AuthModule);
export {
  Session,
  Public,
  Optional,
  Hook,
  BeforeHook,
  AuthService,
  AuthModule,
  AuthGuard,
  AfterHook
};
