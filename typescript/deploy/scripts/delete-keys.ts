import { deleteAgentGCPKeys } from '../src/agents/gcp';
import { getEnvironment, getChainConfigsRecord } from './utils';

async function main() {
  const environment = await getEnvironment();
  const chains = await getChainConfigsRecord(environment);

  return deleteAgentGCPKeys(
    environment,
    Object.values(chains).map((c) => c.name),
  );
}

main().then(console.log).catch(console.error);