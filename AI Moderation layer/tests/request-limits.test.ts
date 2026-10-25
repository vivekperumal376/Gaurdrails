import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { loadTokenPolicy } from "../src/limits.js";
import { createRequestBudgetMiddleware } from "../src/middleware/request-limits.middleware.js";
import { resolve } from "node:path";

const basePolicy = loadTokenPolicy(resolve("config/token-policy.yaml"));

function createBudgetTestApp(policy = basePolicy) {
  const app = express();
  app.use((_req, res, next) => {
    res.locals.requestId = "req_budget_test";
    next();
  });
  app.use(createRequestBudgetMiddleware(policy));
  return app;
}

describe("Phase 06 request budget", () => {
  it("returns 504 when a request exceeds its time budget", async () => {
    const app = createBudgetTestApp({ ...basePolicy, timeoutBudgetMs: 15 });
    app.get("/stall", () => undefined);

    const response = await request(app).get("/stall");

    expect(response.status).toBe(504);
    expect(response.body.error).toBe("REQUEST_TIMEOUT");
    expect(response.body.requestId).toBe("req_budget_test");
  });

  it("rejects requests over the configured concurrency cap", async () => {
    const app = createBudgetTestApp({
      ...basePolicy,
      timeoutBudgetMs: 500,
      maxConcurrentRequests: 1
    });
    let signalStarted: () => void = () => undefined;
    const started = new Promise<void>((resolveStarted) => {
      signalStarted = resolveStarted;
    });
    app.get("/hold", (_req, res) => {
      signalStarted();
      setTimeout(() => res.status(200).json({ status: "DONE" }), 80);
    });

    const firstRequest = request(app).get("/hold").then((response) => response);
    await started;
    const concurrentRequest = await request(app).get("/hold");
    const firstResponse = await firstRequest;

    expect(concurrentRequest.status).toBe(503);
    expect(concurrentRequest.body.error).toBe("CONCURRENCY_LIMIT_EXCEEDED");
    expect(firstResponse.status).toBe(200);
  });
});
