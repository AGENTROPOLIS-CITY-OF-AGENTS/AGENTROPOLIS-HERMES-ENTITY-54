export class LinearError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.code = code;
    }
}
const ISSUE_CREATE_MUTATION = `
mutation IssueCreate($input: IssueCreateInput!) {
  issueCreate(input: $input) {
    success
    issue { id identifier url }
  }
}`;
export function validateIssueInput(input) {
    if (typeof input !== "object" || input === null || Array.isArray(input)) {
        throw new LinearError("invalid_input", "issue input must be an object");
    }
    const record = input;
    if (typeof record.teamId !== "string" || record.teamId.trim().length === 0) {
        throw new LinearError("invalid_input", "teamId is required");
    }
    if (typeof record.title !== "string" || record.title.trim().length === 0) {
        throw new LinearError("invalid_input", "title is required");
    }
    if (record.title.length > 256) {
        throw new LinearError("invalid_input", "title must be 256 characters or fewer");
    }
    if (record.description !== undefined && typeof record.description !== "string") {
        throw new LinearError("invalid_input", "description must be a string");
    }
    if (record.description !== undefined && record.description.length > 10000) {
        throw new LinearError("invalid_input", "description must be 10000 characters or fewer");
    }
    if (record.priority !== undefined) {
        if (typeof record.priority !== "number" || !Number.isInteger(record.priority) || record.priority < 0 || record.priority > 4) {
            throw new LinearError("invalid_input", "priority must be an integer from 0 to 4");
        }
    }
    return {
        teamId: record.teamId.trim(),
        title: record.title.trim(),
        description: typeof record.description === "string" ? record.description : undefined,
        priority: typeof record.priority === "number" ? record.priority : undefined,
    };
}
export function createLinearClient(options) {
    let mockCounter = 0;
    return {
        async createIssue(input) {
            if (options.transport === "mock") {
                mockCounter += 1;
                const issueId = `mock-issue-${mockCounter}`;
                return {
                    issueId,
                    url: `mock://linear/${issueId}`,
                    transport: "mock",
                };
            }
            if (!options.apiKey) {
                throw new LinearError("not_configured", "Linear is not configured: set LINEAR_API_KEY in the profile environment. Refusing to create an issue without credentials.");
            }
            const controller = new AbortController();
            let timeoutId;
            const timeoutPromise = new Promise((_resolve, reject) => {
                timeoutId = setTimeout(() => {
                    controller.abort();
                    reject(new LinearError("timeout", `Linear API timed out after ${options.timeoutMs}ms; failing closed`));
                }, options.timeoutMs);
            });
            try {
                const fetchImpl = options.fetchImpl ??
                    (async (url, init) => {
                        const response = await fetch(url, {
                            method: init.method,
                            headers: init.headers,
                            body: init.body,
                            signal: init.signal,
                        });
                        return { ok: response.ok, status: response.status, text: () => response.text() };
                    });
                const response = await Promise.race([
                    fetchImpl("https://api.linear.app/graphql", {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            Authorization: `Bearer ${options.apiKey}`,
                        },
                        body: JSON.stringify({
                            query: ISSUE_CREATE_MUTATION,
                            variables: { input: { teamId: input.teamId, title: input.title, description: input.description, priority: input.priority } },
                        }),
                        signal: controller.signal,
                    }),
                    timeoutPromise,
                ]);
                const text = await response.text();
                if (!response.ok) {
                    throw new LinearError("linear_http", `Linear API returned HTTP ${response.status}`);
                }
                let parsed;
                try {
                    parsed = JSON.parse(text);
                }
                catch {
                    throw new LinearError("linear_http", "Linear API returned non-JSON");
                }
                const data = parsed.data;
                const errors = parsed.errors;
                if (errors && errors.length > 0) {
                    throw new LinearError("linear_api", errors.map((error) => error.message).join("; "));
                }
                const created = data?.issueCreate;
                if (!created || created.success !== true) {
                    throw new LinearError("linear_api", "Linear issueCreate did not report success");
                }
                const issue = created.issue;
                return {
                    issueId: String(issue.id),
                    url: String(issue.url),
                    transport: "live",
                };
            }
            catch (error) {
                if (error instanceof LinearError) {
                    throw error;
                }
                if (error instanceof Error && error.name === "AbortError") {
                    throw new LinearError("timeout", `Linear API timed out after ${options.timeoutMs}ms; failing closed`);
                }
                throw new LinearError("linear_http", error instanceof Error ? error.message : "Linear request failed");
            }
            finally {
                if (timeoutId !== undefined) {
                    clearTimeout(timeoutId);
                }
            }
        },
    };
}
