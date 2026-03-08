import { InvariantAgent, type AgentConfig } from './index.js'

export async function startInvariantAgent(config: AgentConfig = {}): Promise<InvariantAgent> {
    const agent = new InvariantAgent({ autoConfigure: true, ...config })
    await agent.start()
    return agent
}
