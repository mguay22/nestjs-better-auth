import { Inject, Injectable } from "@nestjs/common";
import type { CanActivate, ExecutionContext } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { GqlExecutionContext } from "@nestjs/graphql";
import type { Auth } from "better-auth";
import { APIError, type getSession } from "better-auth/api";
import { fromNodeHeaders } from "better-auth/node";
import type { Request } from "express";
import { AUTH_INSTANCE_KEY } from "./symbols.ts";

// Extend the Express Request interface to include session and user properties
declare global {
  namespace Express {
    interface Request {
      session?: NonNullable<Awaited<ReturnType<ReturnType<typeof getSession>>>>;
      user?:
        | NonNullable<
            Awaited<ReturnType<ReturnType<typeof getSession>>>
          >["user"]
        | null;
    }
  }
}

/**
 * Type representing a valid user session after authentication
 * Excludes null and undefined values from the session return type
 */
export type UserSession = NonNullable<
  Awaited<ReturnType<ReturnType<typeof getSession>>>
>;

/**
 * NestJS guard that handles authentication for protected routes
 * Can be configured with @Public() or @Optional() decorators to modify authentication behavior
 * Supports both HTTP and GraphQL contexts
 */
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    @Inject(Reflector)
    private readonly reflector: Reflector,
    @Inject(AUTH_INSTANCE_KEY)
    private readonly auth: Auth
  ) {}

  /**
   * Validates if the current request is authenticated
   * Attaches session and user information to the request object or GraphQL context
   * @param context - The execution context of the current request
   * @returns True if the request is authorized to proceed, throws an error otherwise
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isGraphQL = context.getType<"graphql">() === "graphql";
    let request: Request;

    if (isGraphQL) {
      const gqlContext = GqlExecutionContext.create(context);
      request = gqlContext.getContext().req;
    } else {
      request = context.switchToHttp().getRequest();
    }

    const session = await this.auth.api.getSession({
      headers: fromNodeHeaders(request.headers),
    });

    request.session = session;
    request.user = session?.user ?? null; // useful for observability tools like Sentry

    // For GraphQL, also add to context
    if (isGraphQL) {
      const gqlContext = GqlExecutionContext.create(context);
      const ctx = gqlContext.getContext();
      ctx.session = session;
      ctx.user = session?.user ?? null;
    }

    const isPublic = this.reflector.getAllAndOverride<boolean>("PUBLIC", [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) return true;

    const isOptional = this.reflector.getAllAndOverride<boolean>("OPTIONAL", [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isOptional && !session) return true;

    if (!session)
      throw new APIError(401, {
        code: "UNAUTHORIZED",
        message: "Unauthorized",
      });

    return true;
  }
}
