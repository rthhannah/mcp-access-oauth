import { env } from "cloudflare:workers";
import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/server";
import {
  createMcpHandler,
  getMcpAuthContext
} from "agents/mcp/server";
import { z } from "zod";
import { handleAccessRequest } from "./access-handler";
import type { Props } from "./workers-oauth-utils";

// Nur diese E-Mail-Adresse darf Oura-Daten abrufen.
const ALLOWED_EMAILS = new Set([
  "hannah.me2001@gmx.de"
]);

const OURA_API = "https://api.ouraring.com/v2";
const OURA_AUTH = "https://api.ouraring.com";

type OuraTokens = {
  access_token: string;
  refresh_token: string | null;
  expires_at: number;
};

// Prüft die Berechtigung bei jedem Werkzeugaufruf.
function requireAuthorizedUser() {
  const props = getMcpAuthContext()?.props as
    | Props
    | undefined;

  if (
    !props?.email ||
    !ALLOWED_EMAILS.has(props.email.toLowerCase())
  ) {
    throw new Error(
      "Access denied: You are not authorized to access Oura data."
    );
  }
}

async function saveTokens(tokens: {
  access_token: string;
  refresh_token?: string | null;
  expires_in?: number;
}) {
  if (!tokens.access_token) {
    throw new Error("Missing Oura access token");
  }

  await env.OURA_KV.put(
    "oura_tokens",
    JSON.stringify({
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token || null,
      expires_at:
        Date.now() + Number(tokens.expires_in || 86400) * 1000
    })
  );
}

async function exchangeToken(
  params: Record<string, string>
) {
  const credentials = btoa(
    env.OURA_CLIENT_ID + ":" + env.OURA_CLIENT_SECRET
  );

  const response = await fetch(
    OURA_AUTH + "/oauth/token",
    {
      method: "POST",
      headers: {
        Authorization: "Basic " + credentials,
        "Content-Type":
          "application/x-www-form-urlencoded",
        Accept: "application/json"
      },
      body: new URLSearchParams(params)
    }
  );

  if (!response.ok) {
    throw new Error(
      "Oura token refresh failed: HTTP " +
        response.status
    );
  }

  return response.json() as Promise<{
    access_token: string;
    refresh_token?: string;
    expires_in?: number;
  }>;
}

async function getTokens(): Promise<OuraTokens> {
  const tokens = await env.OURA_KV.get<OuraTokens>(
    "oura_tokens",
    "json"
  );

  if (!tokens) {
    throw new Error(
      "No Oura connection found. Please reconnect Oura."
    );
  }

  if (tokens.expires_at > Date.now() + 120000) {
    return tokens;
  }

  if (!tokens.refresh_token) {
    throw new Error(
      "Oura authorization expired. Please reconnect Oura."
    );
  }

  const refreshed = await exchangeToken({
    grant_type: "refresh_token",
    refresh_token: tokens.refresh_token
  });

  await saveTokens({
    ...refreshed,
    refresh_token:
      refreshed.refresh_token || tokens.refresh_token
  });

  const updated = await env.OURA_KV.get<OuraTokens>(
    "oura_tokens",
    "json"
  );

  if (!updated) {
    throw new Error(
      "Unable to load refreshed Oura token"
    );
  }

  return updated;
}

async function getOuraData(
  endpoint: string,
  startDate: string,
  endDate: string
) {
  const tokens = await getTokens();

  const url = new URL(
    OURA_API + "/usercollection/" + endpoint
  );

  url.searchParams.set("start_date", startDate);
  url.searchParams.set("end_date", endDate);

  const response = await fetch(url.toString(), {
    headers: {
      Authorization:
        "Bearer " + tokens.access_token,
      Accept: "application/json"
    }
  });

  if (!response.ok) {
  const errorBody = await response.text();

  console.error(
    "Oura API error:",
    response.status,
    errorBody
  );

  throw new Error(
    "Oura API request failed: HTTP " +
      response.status +
      " - " +
      errorBody
  );
}

const dateSchema = z.object({
  start_date: z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/)
    .describe("Start date in YYYY-MM-DD format"),

  end_date: z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/)
    .describe("End date in YYYY-MM-DD format")
});

function createServer() {
  const server = new McpServer({
    name: "Oura MCP",
    version: "1.0.1"
  });

  // Werkzeuge werden immer registriert.
  // Die Berechtigung wird bei jedem Aufruf geprüft.

  server.registerTool(
    "get_sleep",
    {
      description:
        "Get Oura daily sleep scores and sleep data for a date range.",
      inputSchema: dateSchema
    },
    async ({ start_date, end_date }) => {
      try {
        requireAuthorizedUser();

        const data = await getOuraData(
          "daily_sleep",
          start_date,
          end_date
        );

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(data)
            }
          ]
        };
      } catch (error) {
        return {
          isError: true,
          content: [
            {
              type: "text" as const,
              text:
                error instanceof Error
                  ? error.message
                  : "Unknown Oura error"
            }
          ]
        };
      }
    }
  );

  server.registerTool(
    "get_readiness",
    {
      description:
        "Get Oura daily readiness scores for a date range.",
      inputSchema: dateSchema
    },
    async ({ start_date, end_date }) => {
      try {
        requireAuthorizedUser();

        const data = await getOuraData(
          "daily_readiness",
          start_date,
          end_date
        );

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(data)
            }
          ]
        };
      } catch (error) {
        return {
          isError: true,
          content: [
            {
              type: "text" as const,
              text:
                error instanceof Error
                  ? error.message
                  : "Unknown Oura error"
            }
          ]
        };
      }
    }
  );

  server.registerTool(
    "get_activity",
    {
      description:
        "Get Oura daily activity data for a date range.",
      inputSchema: dateSchema
    },
    async ({ start_date, end_date }) => {
      try {
        requireAuthorizedUser();

        const data = await getOuraData(
          "daily_activity",
          start_date,
          end_date
        );

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(data)
            }
          ]
        };
      } catch (error) {
        return {
          isError: true,
          content: [
            {
              type: "text" as const,
              text:
                error instanceof Error
                  ? error.message
                  : "Unknown Oura error"
            }
          ]
        };
      }
    }
  );
  // Zusätzliche Oura-Daten für den persönlichen Trainer

  const extraTools = [
    {
      name: "get_workouts",
      description: "Get recorded workouts, including activity type, duration and intensity.",
      endpoint: "workout",
    },
    {
      name: "get_sessions",
      description: "Get Oura guided and unguided sessions.",
      endpoint: "session",
    },
    {
      name: "get_detailed_sleep",
      description: "Get detailed sleep periods and available sleep measurements.",
      endpoint: "sleep",
    },
    {
      name: "get_daily_stress",
      description: "Get daily stress and recovery measurements.",
      endpoint: "daily_stress",
    },
    {
      name: "get_daily_resilience",
      description: "Get daily resilience measurements.",
      endpoint: "daily_resilience",
    },
    {
      name: "get_daily_spo2",
      description: "Get daily blood oxygen measurements recorded during sleep.",
      endpoint: "daily_spo2",
    },
    {
      name: "get_vo2_max",
      description: "Get available Oura VO2 max estimates.",
      endpoint: "vO2_max",
    },
  ] as const;

  for (const tool of extraTools) {
    server.registerTool(
      tool.name,
      {
        description: tool.description,
        inputSchema: dateSchema,
      },
      async ({ start_date, end_date }) => {
        try {
          requireAuthorizedUser();

          const data = await getOuraData(
            tool.endpoint,
            start_date,
            end_date
          );

          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify(data),
              },
            ],
          };
        } catch (error) {
          return {
            isError: true,
            content: [
              {
                type: "text" as const,
                text:
                  error instanceof Error
                    ? error.message
                    : "Unknown Oura error",
              },
            ],
          };
        }
      }
    );
  }
  server.registerTool(
  "get_heart_rate",
  {
    description: "Get Oura heart rate measurements for a datetime range.",
    inputSchema: {
      start_datetime: z.string(),
      end_datetime: z.string(),
    },
  },
  async ({ start_datetime, end_datetime }) => {
    try {
      requireAuthorizedUser();

      const tokens = await getTokens();

      const url = new URL(
        "https://api.ouraring.com/v2/usercollection/heartrate"
      );

      url.searchParams.set("start_datetime", start_datetime);
      url.searchParams.set("end_datetime", end_datetime);

      const response = await fetch(url.toString(), {
        headers: {
          Authorization: `Bearer ${tokens.access_token}`,
        },
      });

      if (!response.ok) {
        throw new Error(
          `Oura API error: ${response.status} ${await response.text()}`
        );
      }

      const data = await response.json();

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(data),
          },
        ],
      };
    } catch (error) {
      return {
        isError: true,
        content: [
          {
            type: "text" as const,
            text:
              error instanceof Error
                ? error.message
                : "Unknown Oura error",
          },
        ],
      };
    }
  }
);
  return server;
}

const mcpHandler = createMcpHandler(createServer);

const apiHandler = {
  fetch(
    request: Request,
    bindings: Env,
    ctx: ExecutionContext
  ) {
    return mcpHandler(request, bindings, ctx);
  }
} satisfies ExportedHandler<Env>;

export default new OAuthProvider({
  allowPlainPKCE: false,
  apiHandler,
  apiRoute: "/mcp",
  authorizeEndpoint: "/authorize",
  clientRegistrationEndpoint: "/register",
  defaultHandler: {
    fetch: handleAccessRequest as any
  },
  tokenEndpoint: "/token"
});
