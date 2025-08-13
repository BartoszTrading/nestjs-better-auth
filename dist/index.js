var import_node_module = require("node:module");
var __create = Object.create;
var __getProtoOf = Object.getPrototypeOf;
var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __toESM = (mod, isNodeMode, target) => {
  target = mod != null ? __create(__getProtoOf(mod)) : {};
  const to = isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target;
  for (let key of __getOwnPropNames(mod))
    if (!__hasOwnProp.call(to, key))
      __defProp(to, key, {
        get: () => mod[key],
        enumerable: true
      });
  return to;
};
var __moduleCache = /* @__PURE__ */ new WeakMap;
var __toCommonJS = (from) => {
  var entry = __moduleCache.get(from), desc;
  if (entry)
    return entry;
  entry = __defProp({}, "__esModule", { value: true });
  if (from && typeof from === "object" || typeof from === "function")
    __getOwnPropNames(from).map((key) => !__hasOwnProp.call(entry, key) && __defProp(entry, key, {
      get: () => from[key],
      enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable
    }));
  __moduleCache.set(from, entry);
  return entry;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, {
      get: all[name],
      enumerable: true,
      configurable: true,
      set: (newValue) => all[name] = () => newValue
    });
};
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

// src/index.ts
var exports_src = {};
__export(exports_src, {
  Session: () => Session,
  Public: () => Public,
  Optional: () => Optional,
  Hook: () => Hook,
  BeforeHook: () => BeforeHook,
  AuthService: () => AuthService,
  AuthModule: () => AuthModule,
  AuthGuard: () => AuthGuard,
  AfterHook: () => AfterHook
});
module.exports = __toCommonJS(exports_src);

// src/decorators.ts
var import_common = require("@nestjs/common");

// src/symbols.ts
var BEFORE_HOOK_KEY = Symbol("BEFORE_HOOK");
var AFTER_HOOK_KEY = Symbol("AFTER_HOOK");
var HOOK_KEY = Symbol("HOOK");
var AUTH_INSTANCE_KEY = Symbol("AUTH_INSTANCE");
var AUTH_MODULE_OPTIONS_KEY = Symbol("AUTH_MODULE_OPTIONS");

// src/utils.ts
var import_graphql = require("@nestjs/graphql");
function getRequestObject(context) {
  if (context.getType() === "http") {
    return context.switchToHttp().getRequest();
  }
  return import_graphql.GqlExecutionContext.create(context).getContext().req;
}
function getResponseObject(host) {
  const type = host.getType();
  if (type === "http") {
    return host.switchToHttp().getResponse();
  }
  return import_graphql.GqlArgumentsHost.create(host).getContext().res;
}

// src/decorators.ts
var Public = () => import_common.SetMetadata("PUBLIC", true);
var Optional = () => import_common.SetMetadata("OPTIONAL", true);
var Session = import_common.createParamDecorator((_data, context) => {
  const request = getRequestObject(context);
  return request.session;
});
var BeforeHook = (path) => import_common.SetMetadata(BEFORE_HOOK_KEY, path);
var AfterHook = (path) => import_common.SetMetadata(AFTER_HOOK_KEY, path);
var Hook = () => import_common.SetMetadata(HOOK_KEY, true);
// src/auth-service.ts
var import_common2 = require("@nestjs/common");
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
  __legacyDecorateParamTS(0, import_common2.Inject(AUTH_INSTANCE_KEY)),
  __legacyMetadataTS("design:paramtypes", [
    typeof T === "undefined" ? Object : T
  ])
], AuthService);
// src/auth-guard.ts
var import_common3 = require("@nestjs/common");
var import_core = require("@nestjs/core");
var import_api = require("better-auth/api");
var import_node = require("better-auth/node");
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
      headers: import_node.fromNodeHeaders(request.headers)
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
      throw new import_api.APIError(401, {
        code: "UNAUTHORIZED",
        message: "Unauthorized"
      });
    return true;
  }
}
AuthGuard = __legacyDecorateClassTS([
  import_common3.Injectable(),
  __legacyDecorateParamTS(0, import_common3.Inject(import_core.Reflector)),
  __legacyDecorateParamTS(1, import_common3.Inject(AUTH_INSTANCE_KEY)),
  __legacyMetadataTS("design:paramtypes", [
    typeof import_core.Reflector === "undefined" ? Object : import_core.Reflector,
    typeof Auth === "undefined" ? Object : Auth
  ])
], AuthGuard);
// src/auth-module.ts
var import_common6 = require("@nestjs/common");
var import_core2 = require("@nestjs/core");
var import_node2 = require("better-auth/node");
var import_plugins = require("better-auth/plugins");

// src/api-error-exception-filter.ts
var import_common4 = require("@nestjs/common");
var import_api2 = require("better-auth/api");
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
  import_common4.Catch(import_api2.APIError)
], APIErrorExceptionFilter);

// src/middlewares.ts
var import_common5 = require("@nestjs/common");
var express = __toESM(require("express"));
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
  import_common5.Injectable()
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
  logger = new import_common6.Logger(AuthModule.name);
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
    const handler = import_node2.toNodeHandler(this.auth);
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
      this.auth.options.hooks[hookType] = import_plugins.createAuthMiddleware(async (ctx) => {
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
        provide: import_core2.APP_FILTER,
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
  import_common6.Module({
    imports: [import_core2.DiscoveryModule]
  }),
  __legacyDecorateParamTS(0, import_common6.Inject(AUTH_INSTANCE_KEY)),
  __legacyDecorateParamTS(1, import_common6.Inject(import_core2.DiscoveryService)),
  __legacyDecorateParamTS(2, import_common6.Inject(import_core2.MetadataScanner)),
  __legacyDecorateParamTS(3, import_common6.Inject(import_core2.HttpAdapterHost)),
  __legacyDecorateParamTS(4, import_common6.Inject(AUTH_MODULE_OPTIONS_KEY)),
  __legacyMetadataTS("design:paramtypes", [
    typeof Auth === "undefined" ? Object : Auth,
    typeof import_core2.DiscoveryService === "undefined" ? Object : import_core2.DiscoveryService,
    typeof import_core2.MetadataScanner === "undefined" ? Object : import_core2.MetadataScanner,
    typeof import_core2.HttpAdapterHost === "undefined" ? Object : import_core2.HttpAdapterHost,
    typeof AuthModuleOptions === "undefined" ? Object : AuthModuleOptions
  ])
], AuthModule);
