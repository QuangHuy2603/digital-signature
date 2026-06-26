import "dotenv/config";
import { getClientAgentClientStatus } from "../src/services/client-agent-client.service.js";

const local = getClientAgentClientStatus();
let remote = null;
try {
    const response = await fetch(`${local.endpoint}/health`);
    remote = await response.json();
} catch (error) {
    remote = { ready: false, error: error.message };
}
console.log(JSON.stringify({ client: local, agent: remote }, null, 2));
